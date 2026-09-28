/* Bounded transport capability probe. Does not elevate, chroot, fork, or write
 * kernel state. The normal payload SDK/loader startup remains a prerequisite. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "native_directory.h"
#include "probe_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef LAPY_PROBE_EXCLUSIVE
#define LAPY_PROBE_EXCLUSIVE 0
#endif

int main(void)
{
    int pair[2] = {-1, -1}, root = -1, received = -1;
    int error = 0, complete = 0;
    const char *stage = "initialization";
    struct stat original, imported;
    if (ps5log_init_default("LAPYPROBE", "lapy-native-probe") != 0)
        return 2;
    ps5log_printf(PS5LOG_MARK, "probe_start build=%s firmware=%08x cycles=64 mode=transport-only receiver=%s",
                  LAPY_PROBE_ID, kernel_get_fw_version(),
                  LAPY_PROBE_EXCLUSIVE ? "exclusive" : "atomic");
    stage = "socketpair";
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0) {
        error = errno;
        goto cleanup;
    }
    stage = "open_root";
    root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) {
        error = errno;
        goto cleanup;
    }
    stage = "stat_root";
    if (fstat(root, &original) < 0) {
        error = errno;
        goto cleanup;
    }
    while (complete < 64) {
        stage = "send_directory";
        error = lapy_send_directory(pair[0], root, (uint64_t)complete + 1);
        if (error) goto cleanup;
        stage = "receive_ready";
        struct pollfd ready = {pair[1], POLLIN, 0};
        int result = poll(&ready, 1, 200);
        if (result <= 0 || !(ready.revents & POLLIN)) {
            error = result < 0 ? errno : ETIMEDOUT;
            goto cleanup;
        }
        stage = "receive_directory";
        /* This probe never executes another image or creates a thread/child;
         * ps5log is synchronous. This does NOT establish exclusion in a target
         * title. An integrated daemon must prove that independently. */
        if (LAPY_PROBE_EXCLUSIVE)
            error = lapy_receive_directory_exclusive(pair[1], (uint64_t)complete + 1,
                                                      &received, &stage);
        else
            error = lapy_receive_directory_diagnostic(pair[1], (uint64_t)complete + 1,
                                                      &received, &stage);
        if (error) goto cleanup;
        stage = "identity";
        if (fstat(received, &imported) < 0) {
            error = errno;
            goto cleanup;
        }
        if (original.st_dev != imported.st_dev || original.st_ino != imported.st_ino ||
            !S_ISDIR(imported.st_mode)) {
            error = EPROTO;
            goto cleanup;
        }
        stage = "close_received";
        result = close(received);
        received = -1;
        if (result < 0) {
            error = errno;
            goto cleanup;
        }
        ++complete;
    }
    stage = "complete";
cleanup:
    if (received >= 0) close(received);
    if (root >= 0) close(root);
    if (pair[0] >= 0) close(pair[0]);
    if (pair[1] >= 0) close(pair[1]);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d completed=%d expected=64",
                  LAPY_PROBE_ID, stage, error, complete);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
