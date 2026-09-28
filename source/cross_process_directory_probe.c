/* Native root-directory descriptor transfer between disposable processes.
 * Neither process elevates or writes kernel memory. The child closes its
 * inherited root descriptor before receiving a fresh SCM_RIGHTS reference. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "native_directory.h"
#include "probe_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define WAIT_MS 5000
#define CHILD_ALARM 15

static int read_ready(int fd, char *value)
{
    struct pollfd ready = {fd, POLLIN, 0};
    int result = poll(&ready, 1, WAIT_MS);
    if (result <= 0) return result < 0 ? errno : ETIMEDOUT;
    return read(fd, value, 1) == 1 ? 0 : EPIPE;
}

static int read_error(int fd, int *error)
{
    struct pollfd ready = {fd, POLLIN, 0};
    int result = poll(&ready, 1, WAIT_MS);
    if (result <= 0) return result < 0 ? errno : ETIMEDOUT;
    return read(fd, error, sizeof(*error)) == sizeof(*error) ? 0 : EPIPE;
}

static void child_run(int sender, int receiver, int root,
                      int child_to_parent[2], int parent_to_child[2],
                      const struct stat *expected)
{
    struct stat imported;
    int received = -1, error = 0;
    char phase = 'E', go = 0;
    const char *receive_stage = 0;
    close(sender);
    close(child_to_parent[0]);
    close(parent_to_child[1]);
    alarm(CHILD_ALARM);
    if (close(root)) { error = errno ? errno : EIO; goto done; }
    if (write(child_to_parent[1], "R", 1) != 1) {
        error = EPIPE;
        goto done;
    }
    {
        struct pollfd ready = {receiver, POLLIN, 0};
        int result = poll(&ready, 1, WAIT_MS);
        if (result <= 0) { error = result < 0 ? errno : ETIMEDOUT; goto done; }
    }
    error = lapy_receive_directory_exclusive(receiver, 1, &received,
                                             &receive_stage);
    if (error) goto done;
    phase = 'D';
    if (write(child_to_parent[1], &phase, 1) != 1) {
        error = EPIPE;
        goto done;
    }
    if (read_ready(parent_to_child[0], &go) || go != 'G') {
        error = EPROTO;
        goto done;
    }
    if (fstat(received, &imported) ||
        imported.st_dev != expected->st_dev ||
        imported.st_ino != expected->st_ino ||
        !S_ISDIR(imported.st_mode)) {
        error = EPROTO;
        goto done;
    }
    {
        int flags = fcntl(received, F_GETFD);
        if (flags < 0 || !(flags & FD_CLOEXEC)) {
            error = flags < 0 ? errno : ENOTSUP;
            goto done;
        }
    }
done:
    if (received >= 0 && close(received) && !error)
        error = errno ? errno : EIO;
    close(receiver);
    if (phase != 'D') write(child_to_parent[1], "E", 1);
    write(child_to_parent[1], &error, sizeof(error));
    close(child_to_parent[1]);
    close(parent_to_child[0]);
    _exit(error ? 1 : 0);
}

int main(void)
{
    int pair[2] = {-1, -1}, child_to_parent[2] = {-1, -1};
    int parent_to_child[2] = {-1, -1}, root = -1;
    int error = 0, child_error = -1, wait_status = 0;
    int parent_root_closed = 0, child_after_close = 0;
    const char *stage = "socketpair";
    void (*old_sigpipe)(int) = SIG_ERR;
    struct stat original;
    pid_t child = -1;
    char phase = 0;

    if (ps5log_init_default("LAPYXFD", "lapy-cross-process-directory-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=cross-process-root-fd",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    old_sigpipe = signal(SIGPIPE, SIG_IGN);
    if (old_sigpipe == SIG_ERR) { error = errno ? errno : EIO; goto done; }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair)) {
        error = errno ? errno : EIO;
        goto done;
    }
    stage = "open_root";
    root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0 || fstat(root, &original) || !S_ISDIR(original.st_mode)) {
        error = errno ? errno : EIO;
        goto done;
    }
    stage = "pipes";
    if (pipe(child_to_parent) || pipe(parent_to_child)) {
        error = errno ? errno : EIO;
        goto done;
    }
    stage = "rfork";
    child = rfork(RFPROC | RFFDG);
    if (child == 0)
        child_run(pair[0], pair[1], root, child_to_parent,
                  parent_to_child, &original);
    if (child < 0) { error = errno ? errno : EIO; goto done; }
    close(pair[1]); pair[1] = -1;
    close(child_to_parent[1]); child_to_parent[1] = -1;
    close(parent_to_child[0]); parent_to_child[0] = -1;

    stage = "child_ready";
    error = read_ready(child_to_parent[0], &phase);
    if (error || phase != 'R') { if (!error) error = EPROTO; goto done; }
    stage = "send_directory";
    error = lapy_send_directory(pair[0], root, 1);
    if (error) goto done;
    stage = "child_received";
    error = read_ready(child_to_parent[0], &phase);
    if (error || phase != 'D') {
        if (!error) error = EPROTO;
        goto done;
    }
    stage = "sender_close";
    if (close(root)) { error = errno ? errno : EIO; goto done; }
    root = -1;
    parent_root_closed = 1;
    if (write(parent_to_child[1], "G", 1) != 1) {
        error = EPIPE;
        goto done;
    }
    stage = "child_result";
    error = read_error(child_to_parent[0], &child_error);
    if (error) goto done;
    if (child_error) { error = child_error; goto done; }
    child_after_close = 1;
    stage = "complete";
done:
    if (root >= 0) close(root);
    for (unsigned i = 0; i < 2; ++i) {
        if (pair[i] >= 0) close(pair[i]);
        if (child_to_parent[i] >= 0) close(child_to_parent[i]);
        if (parent_to_child[i] >= 0) close(parent_to_child[i]);
    }
    if (child > 0 && (waitpid(child, &wait_status, 0) != child ||
                      !WIFEXITED(wait_status) || WEXITSTATUS(wait_status))) {
        if (!error) error = ECHILD;
    }
    if (old_sigpipe != SIG_ERR) signal(SIGPIPE, old_sigpipe);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d child_error=%d parent_root_closed=%d child_after_close=%d child_reaped=%d",
                  LAPY_PROBE_ID, stage, error, child_error,
                  parent_root_closed, child_after_close,
                  child > 0 && WIFEXITED(wait_status));
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
