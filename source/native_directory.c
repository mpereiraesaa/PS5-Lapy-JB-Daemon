#include "native_directory.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

enum { PACKET_BYTES = 16, MAX_RIGHTS = 8 };

static void packet(unsigned char bytes[PACKET_BYTES], uint64_t id)
{
    const unsigned char magic[8] = {'L', 'A', 'P', 'Y', 'D', 'I', 'R', 1};
    memcpy(bytes, magic, sizeof(magic));
    for (unsigned i = 0; i < 8; ++i)
        bytes[8 + i] = (unsigned char)(id >> (8 * i));
}

static int check_socket(int fd)
{
    int type;
    socklen_t length = sizeof(type);
    struct sockaddr_storage address;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) < 0)
        return errno;
    if (type != SOCK_SEQPACKET)
        return EPROTOTYPE;
    length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) < 0)
        return errno;
    if (address.ss_family != AF_UNIX)
        return EAFNOSUPPORT;
    return 0;
}

int lapy_send_directory(int socket_fd, int directory_fd, uint64_t request_id)
{
    unsigned char bytes[PACKET_BYTES];
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    struct stat st;
    struct msghdr message;
    struct iovec vector;
    struct cmsghdr *header;
    ssize_t sent;
    int error = check_socket(socket_fd);
    if (error)
        return error;
    if (fstat(directory_fd, &st) < 0)
        return errno;
    if (!S_ISDIR(st.st_mode))
        return ENOTDIR;
    packet(bytes, request_id);
    memset(&control, 0, sizeof(control));
    memset(&message, 0, sizeof(message));
    vector.iov_base = bytes;
    vector.iov_len = sizeof(bytes);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &directory_fd, sizeof(directory_fd));
    sent = sendmsg(socket_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0)
        return errno;
    return sent == (ssize_t)sizeof(bytes) ? 0 : EIO;
}

int lapy_receive_directory(int socket_fd, uint64_t request_id, int *directory_fd)
{
    unsigned char bytes[PACKET_BYTES], expected[PACKET_BYTES];
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(MAX_RIGHTS * sizeof(int))]; } control;
    struct msghdr message;
    struct iovec vector;
    struct cmsghdr *header;
    struct stat st;
    int received[MAX_RIGHTS];
    unsigned count = 0;
    int error;
    ssize_t size;
    if (!directory_fd)
        return EINVAL;
    *directory_fd = -1;
    if ((error = check_socket(socket_fd)))
        return error;
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = bytes;
    vector.iov_len = sizeof(bytes);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    size = recvmsg(socket_fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (size < 0)
        return errno;
    error = 0;
    for (header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) {
            error = EPROTO;
            continue;
        }
        if (header->cmsg_len < CMSG_LEN(0)) {
            error = EPROTO;
            break;
        }
        size_t payload = header->cmsg_len - CMSG_LEN(0);
        if (payload % sizeof(int))
            error = EPROTO;
        for (size_t i = 0; i + sizeof(int) <= payload; i += sizeof(int)) {
            int fd;
            memcpy(&fd, CMSG_DATA(header) + i, sizeof(fd));
            if (count < MAX_RIGHTS)
                received[count++] = fd;
            else {
                close(fd);
                error = EMSGSIZE;
            }
        }
    }
    packet(expected, request_id);
    if (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
        error = EMSGSIZE;
    else if (size != PACKET_BYTES || memcmp(bytes, expected, sizeof(bytes)) || count != 1)
        error = EPROTO;
    if (!error) {
        int flags = fcntl(received[0], F_GETFD);
        if (flags < 0)
            error = errno;
        else if (!(flags & FD_CLOEXEC))
            error = ENOTSUP;
        else if (fstat(received[0], &st) < 0)
            error = errno;
        else if (!S_ISDIR(st.st_mode))
            error = ENOTDIR;
    }
    if (error) {
        for (unsigned i = 0; i < count; ++i)
            close(received[i]);
        return error;
    }
    *directory_fd = received[0];
    return 0;
}
