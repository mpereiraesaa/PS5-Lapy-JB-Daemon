#define _GNU_SOURCE
#include "native_directory.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int open_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    assert(directory);
    int count = 0;
    while (readdir(directory))
        ++count;
    assert(closedir(directory) == 0);
    return count;
}

static void bad_packet(int socket, int fd, unsigned count, size_t payload_size)
{
    unsigned char bytes[17] = {'L', 'A', 'P', 'Y', 'D', 'I', 'R', 1, 42};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(32 * sizeof(int))]; } control;
    struct iovec vector = {bytes, payload_size};
    struct msghdr message = {0};
    assert(count <= 32);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (count) {
        memset(&control, 0, sizeof(control));
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        for (unsigned i = 0; i < count; ++i)
            memcpy(CMSG_DATA(header) + i * sizeof(int), &fd, sizeof(fd));
    }
    assert(sendmsg(socket, &message, MSG_NOSIGNAL) == (ssize_t)payload_size);
}

int main(void)
{
    int baseline = open_count();
    int pair[2], received = -1;
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0);
    int root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(root >= 0);
    int error = lapy_receive_directory(pair[1], 42, &received);
    assert((error == EAGAIN || error == EWOULDBLOCK) && received == -1);
    int steady = open_count();
    for (int i = 0; i < 1000; ++i) {
        assert(lapy_send_directory(pair[0], root, 42) == 0);
        assert(lapy_receive_directory(pair[1], 42, &received) == 0);
        assert(received != root && (fcntl(received, F_GETFD) & FD_CLOEXEC));
        struct stat a, b;
        assert(fstat(root, &a) == 0 && fstat(received, &b) == 0);
        assert(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
        assert(close(received) == 0);
    }
    assert(open_count() == steady);
    assert(lapy_send_directory(pair[0], root, 43) == 0);
    assert(lapy_receive_directory(pair[1], 42, &received) == EPROTO && received == -1);
    assert(open_count() == steady);
    for (unsigned count = 0; count <= 32; count += 2) {
        bad_packet(pair[0], root, count, 16);
        assert(lapy_receive_directory(pair[1], 42, &received) != 0 && received == -1);
        assert(open_count() == steady);
    }
    for (size_t size = 0; size <= 17; ++size) {
        if (size == 16) continue;
        bad_packet(pair[0], root, 1, size);
        assert(lapy_receive_directory(pair[1], 42, &received) != 0 && received == -1);
        assert(open_count() == steady);
    }
    int regular = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(regular >= 0);
    assert(lapy_send_directory(pair[0], regular, 42) == ENOTDIR);
    bad_packet(pair[0], regular, 1, 16);
    assert(lapy_receive_directory(pair[1], 42, &received) == ENOTDIR && received == -1);
    close(regular);
    assert(open_count() == steady);

    /* Actual cross-process ownership: the receiver can use the directory after
     * the sender closes its descriptor. No chroot/elevation occurs in this test. */
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(pair[0]);
        close(root);
        int result = EAGAIN;
        for (unsigned attempt = 0; attempt < 2000; ++attempt) {
            result = lapy_receive_directory(pair[1], 99, &received);
            if (result != EAGAIN && result != EWOULDBLOCK) break;
            usleep(1000);
        }
        assert(result == 0);
        assert(fchdir(received) == 0);
        char cwd[8];
        assert(getcwd(cwd, sizeof(cwd)) && strcmp(cwd, "/") == 0);
        close(received);
        close(pair[1]);
        _exit(0);
    }
    close(pair[1]);
    assert(lapy_send_directory(pair[0], root, 99) == 0);
    close(root);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(pair[0]);
    assert(open_count() == baseline);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(lapy_receive_directory(pair[1], 42, &received) == EPROTOTYPE);
    close(pair[0]); close(pair[1]);
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0);
    root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(root >= 0);
    close(pair[1]);
    assert(lapy_send_directory(pair[0], root, 1) != 0); /* Must not raise SIGPIPE. */
    close(root); close(pair[0]);
    assert(open_count() == baseline);
    puts("native directory transport: ownership, truncation, rejection and 1000 cycles passed");
    return 0;
}
