/* FW 12.02 disposable remote native seteuid clone probe. The host debugger
 * may execute only the child's verified syscall gadget; this payload makes no
 * kernel writes and never edits a title's credential. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROC_PID_OFFSET 0xbcu
#define PROC_SUSPCOUNT 0x3a0u

__attribute__((naked, noinline, used)) static void syscall_gadget(void)
{
    __asm__ volatile("syscall\nint3\n");
}

struct ready_message {
    uint32_t marker;
    uint32_t euid;
    uintptr_t gadget;
};

struct credential {
    intptr_t proc, pointer;
    uint32_t uid, ruid, svuid, rgid;
    uint64_t authid, attrs;
    uint8_t caps[16];
};

static int snapshot(pid_t pid, struct credential *out)
{
    pid_t observed = 0;
    memset(out, 0, sizeof(*out));
    out->proc = kernel_get_proc(pid);
    if (!out->proc || kernel_copyout(out->proc + PROC_PID_OFFSET,
                                      &observed, sizeof(observed)) ||
        observed != pid) return ESRCH;
    out->pointer = kernel_get_proc_ucred(pid);
    if (!out->pointer ||
        kernel_copyout(out->pointer + KERNEL_OFFSET_UCRED_CR_UID,
                       &out->uid, sizeof(out->uid)) ||
        kernel_copyout(out->pointer + KERNEL_OFFSET_UCRED_CR_RUID,
                       &out->ruid, sizeof(out->ruid)) ||
        kernel_copyout(out->pointer + KERNEL_OFFSET_UCRED_CR_SVUID,
                       &out->svuid, sizeof(out->svuid)) ||
        kernel_copyout(out->pointer + KERNEL_OFFSET_UCRED_CR_RGID,
                       &out->rgid, sizeof(out->rgid)) ||
        kernel_copyout(out->pointer + KERNEL_OFFSET_UCRED_CR_SCEAUTHID,
                       &out->authid, sizeof(out->authid)) ||
        kernel_copyout(out->pointer + KERNEL_OFFSET_UCRED_CR_SCEATTRS,
                       &out->attrs, sizeof(out->attrs)) ||
        kernel_copyout(out->pointer + KERNEL_OFFSET_UCRED_CR_SCECAPS,
                       out->caps, sizeof(out->caps))) return EFAULT;
    return 0;
}

static int preserved(const struct credential *a, const struct credential *b)
{
    return a->proc == b->proc && a->uid == b->uid &&
           a->ruid == b->ruid && a->svuid == b->svuid &&
           a->rgid == b->rgid && a->authid == b->authid &&
           a->attrs == b->attrs && !memcmp(a->caps, b->caps, sizeof(a->caps));
}

static void child_main(int ready[2], int release[2])
{
    char command = 0;
    struct ready_message message = {0x4c435244u, (uint32_t)geteuid(),
                                    (uintptr_t)&syscall_gadget};
    close(ready[0]); close(release[1]);
    alarm(30);
    if (write(ready[1], &message, sizeof(message)) != sizeof(message))
        _exit(2);
    if (read(release[0], &command, 1) != 1 || command != 'G') _exit(3);
    _exit(geteuid() == (uid_t)message.euid ? 0 : 4);
}

int main(void)
{
    int ready[2] = {-1,-1}, release[2] = {-1,-1};
    pid_t child = -1;
    struct ready_message message = {0};
    struct credential before, after, confirmed;
    int error = 0, status = 0, reaped = 0, cloned = 0, host_window = 0;
    const char *stage = "preflight";
    if (ps5log_init_default("LAPYRCL", "lapy-remote-credential-clone")) return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=remote-native-seteuid",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    if (kernel_get_fw_version() != 0x12020000 ||
        KERNEL_OFFSET_PROC_P_PID != PROC_PID_OFFSET) {
        error = ENOTSUP; goto done;
    }
    if (pipe(ready) || pipe(release)) { error = errno ? errno : EIO; goto done; }
    child = rfork(RFPROC | RFFDG);
    if (child == 0) child_main(ready, release);
    if (child < 0) { error = errno ? errno : EIO; goto done; }
    close(ready[1]); ready[1] = -1;
    close(release[0]); release[0] = -1;
    struct pollfd event = {ready[0], POLLIN, 0};
    stage = "child_ready";
    if (poll(&event, 1, 5000) != 1 ||
        read(ready[0], &message, sizeof(message)) != sizeof(message) ||
        message.marker != 0x4c435244u || !message.gadget ||
        (error = snapshot(child, &before)) || before.uid != message.euid) {
        if (!error) error = EPROTO;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "child_ready build=%s pid=%d euid=%u gadget=%llx hold_seconds=12",
                  LAPY_PROBE_ID, (int)child, message.euid,
                  (unsigned long long)message.gadget);
    host_window = 1;
    stage = "remote_clone";
    for (unsigned i = 0; i < 120; ++i) {
        usleep(100000);
        if ((error = snapshot(child, &after))) goto done;
        if (after.proc != before.proc) { error = ESTALE; goto done; }
        if (after.pointer != before.pointer) { cloned = 1; break; }
    }
    if (!cloned) { error = ETIMEDOUT; goto done; }
    usleep(50000);
    if ((error = snapshot(child, &confirmed))) goto done;
    if (confirmed.pointer != after.pointer ||
        !preserved(&before, &after) || !preserved(&before, &confirmed)) {
        error = EPROTO; goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "native_clone_observed build=%s pointer_replaced=1 fields_preserved=1",
                  LAPY_PROBE_ID);
    stage = "child_exit";
    if (write(release[1], "G", 1) != 1) { error = EPIPE; goto done; }
    for (unsigned i = 0; i < 100; ++i) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            reaped = 1;
            if (!WIFEXITED(status) || WEXITSTATUS(status)) error = EPROTO;
            break;
        }
        if (result < 0) { error = errno ? errno : ECHILD; goto done; }
        usleep(100000);
    }
    if (!reaped && !error) error = ETIMEDOUT;
    if (!error) stage = "complete";
done:
    if (host_window && error && child > 0 && !reaped) {
        intptr_t proc = kernel_get_proc(child);
        uint32_t suspended = 0;
        if (proc && (kernel_copyout(proc + PROC_SUSPCOUNT, &suspended,
                                    sizeof(suspended)) || suspended)) {
            ps5log_printf(PS5LOG_ERR,
                          "probe_held build=%s stage=%s error=%d reason=child_stop_or_unknown",
                          LAPY_PROBE_ID, stage, error);
            for (;;) sleep(1);
        }
    }
    if (child > 0 && !reaped) {
        kill(child, SIGCONT);
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (release[0] >= 0) close(release[0]);
    if (release[1] >= 0) close(release[1]);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d cloned=%d reaped=%d",
                  LAPY_PROBE_ID, stage, error, cloned, reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
