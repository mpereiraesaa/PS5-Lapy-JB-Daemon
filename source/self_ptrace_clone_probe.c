/* FW 12.02 disposable target-side native credential clone via payload ptrace.
 * No title or kernel credential pointer is directly modified. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <machine/reg.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#define PTRACE_AUTHID UINT64_C(0x4800000000010003)
#define SYS_SETEUID 183
#define GADGET_BYTES UINT32_C(0x00cc050f)

__attribute__((naked, noinline, used)) static void syscall_gadget(void)
{
    __asm__ volatile("syscall\nint3\n");
}

struct ready_message {
    uint32_t marker, euid;
    uintptr_t gadget;
};

extern intptr_t kernel_get_ucred_prison(pid_t pid);

struct credential {
    intptr_t pointer, prison;
    uid_t uid;
    uint64_t authid, attrs;
    uint8_t caps[16];
};

static int snapshot_credential(pid_t pid, struct credential *out)
{
    memset(out, 0, sizeof(*out));
    out->pointer = kernel_get_proc_ucred(pid);
    out->prison = kernel_get_ucred_prison(pid);
    if (!out->pointer || !out->prison) return EFAULT;
    out->uid = kernel_get_ucred_uid(pid);
    out->authid = kernel_get_ucred_authid(pid);
    out->attrs = kernel_get_ucred_attrs(pid);
    return kernel_get_ucred_caps(pid, out->caps) ? EFAULT : 0;
}

static int same_credential_fields(const struct credential *a,
                                  const struct credential *b)
{
    return a->prison == b->prison && a->uid == b->uid &&
           a->authid == b->authid && a->attrs == b->attrs &&
           !memcmp(a->caps, b->caps, sizeof(a->caps));
}

static void child_main(int ready[2], int release[2])
{
    struct ready_message message = {0x4c505443u, (uint32_t)geteuid(),
                                    (uintptr_t)&syscall_gadget};
    char command = 0;
    close(ready[0]); close(release[1]);
    alarm(30);
    if (write(ready[1], &message, sizeof(message)) != sizeof(message))
        _exit(2);
    if (read(release[0], &command, 1) != 1 || command != 'G') _exit(3);
    _exit(geteuid() == (uid_t)message.euid ? 0 : 4);
}

static int wait_stopped(pid_t child, int *reaped)
{
    int status = 0;
    for (unsigned i = 0; i < 100; ++i) {
        pid_t observed = waitpid(child, &status, WNOHANG | WUNTRACED);
        if (observed == child) {
            if (WIFSTOPPED(status)) return 0;
            *reaped = 1;
            return EPROTO;
        }
        if (observed < 0) return errno ? errno : ECHILD;
        usleep(50000);
    }
    return ETIMEDOUT;
}

static int wait_exit(pid_t child, int *reaped)
{
    int status = 0;
    for (unsigned i = 0; i < 100; ++i) {
        pid_t observed = waitpid(child, &status, WNOHANG);
        if (observed == child) {
            *reaped = 1;
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : EPROTO;
        }
        if (observed < 0) return errno ? errno : ECHILD;
        usleep(50000);
    }
    return ETIMEDOUT;
}

static int ptrace_set(pid_t child, const struct reg *regs)
{
    return ptrace(PT_SETREGS, child, (caddr_t)regs, 0) == 0 ?
           0 : (errno ? errno : EIO);
}

static int ptrace_get(pid_t child, struct reg *regs)
{
    return ptrace(PT_GETREGS, child, (caddr_t)regs, 0) == 0 ?
           0 : (errno ? errno : EIO);
}

int main(void)
{
    int ready[2] = {-1,-1}, release[2] = {-1,-1};
    pid_t child = -1, self = getpid();
    struct ready_message message = {0};
    struct reg original = {0}, injected = {0}, result = {0}, restored = {0};
    struct credential child_cred_before, child_cred_after;
    intptr_t self_cred_before = 0, self_cred_after = 0;
    uint64_t original_authid = 0;
    int error = 0, status = 0, attached = 0, stopped = 0, modified = 0;
    int regs_saved = 0, regs_restored = 0, detached = 0, reaped = 0;
    int auth_changed = 0, auth_restored = 0, cloned = 0;
    const char *stage = "preflight";
    if (ps5log_init_default("LAPYPTC", "lapy-self-ptrace-clone")) return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=payload-ptrace-native-seteuid",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    if (kernel_get_fw_version() != 0x12020000) {
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
        message.marker != 0x4c505443u || !message.gadget) {
        error = EPROTO; goto done;
    }
    if ((error = snapshot_credential(child, &child_cred_before)) ||
        child_cred_before.uid != message.euid) {
        error = EPROTO; goto done;
    }
    self_cred_before = kernel_get_proc_ucred(self);
    original_authid = kernel_get_ucred_authid(self);
    stage = "private_parent_credential";
    if (!self_cred_before || !original_authid || seteuid(geteuid())) {
        error = errno ? errno : EPROTO; goto done;
    }
    self_cred_after = kernel_get_proc_ucred(self);
    if (!self_cred_after || self_cred_after == self_cred_before ||
        kernel_get_ucred_authid(self) != original_authid) {
        error = EPROTO; goto done;
    }
    auth_changed = 1;
    if (kernel_set_ucred_authid(self, PTRACE_AUTHID) ||
        kernel_get_ucred_authid(self) != PTRACE_AUTHID) {
        error = EACCES; goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "child_ready build=%s pid=%d private_parent_credential=1 hold_seconds=12",
                  LAPY_PROBE_ID, (int)child);
    stage = "ptrace_attach";
    if (ptrace(PT_ATTACH, child, 0, 0)) {
        error = errno ? errno : EIO; goto done;
    }
    attached = 1;
    stage = "wait_attach_stop";
    if ((error = wait_stopped(child, &reaped))) goto done;
    stopped = 1;
    stage = "verify_gadget";
    errno = 0;
    long word = ptrace(PT_READ_I, child, (caddr_t)message.gadget, 0);
    if (word == -1 && errno) { error = errno; goto done; }
    if (((uint32_t)word & 0x00ffffffu) != GADGET_BYTES) {
        error = EPROTO; goto done;
    }
    stage = "save_registers";
    if ((error = ptrace_get(child, &original))) goto done;
    regs_saved = 1;
    injected = original;
    injected.r_rip = (int64_t)message.gadget;
    injected.r_rax = SYS_SETEUID;
    injected.r_rdi = message.euid;
    stage = "native_step";
    if ((error = ptrace_set(child, &injected))) goto done;
    modified = 1;
    if (ptrace(PT_STEP, child, (caddr_t)1, 0)) {
        error = errno ? errno : EIO; goto done;
    }
    stopped = 0;
    if ((error = wait_stopped(child, &reaped))) goto done;
    stopped = 1;
    if ((error = ptrace_get(child, &result))) goto done;
    if (result.r_rip != (int64_t)(message.gadget + 2)) {
        error = EPROTO; goto done;
    }
    stage = "restore_registers";
    if ((error = ptrace_set(child, &original)) ||
        (error = ptrace_get(child, &restored)) ||
        memcmp(&restored, &original, sizeof(original))) {
        if (!error) error = EPROTO;
        goto done;
    }
    regs_restored = 1;
    modified = 0;
    if (result.r_rax != 0 || result.r_rflags & 1) {
        error = EACCES; goto done;
    }
    if ((error = snapshot_credential(child, &child_cred_after))) goto done;
    cloned = child_cred_after.pointer != child_cred_before.pointer &&
             same_credential_fields(&child_cred_before, &child_cred_after);
    if (!cloned) { error = EPROTO; goto done; }
    ps5log_printf(PS5LOG_MARK,
                  "native_clone_observed build=%s pointer_replaced=1 fields_preserved=1 prison_preserved=1 registers_restored=1",
                  LAPY_PROBE_ID);
    stage = "detach";
    if (ptrace(PT_DETACH, child, (caddr_t)1, 0)) {
        error = errno ? errno : EIO; goto done;
    }
    detached = 1;
    attached = 0;
    stage = "restore_parent_authid";
    if (kernel_set_ucred_authid(self, original_authid) ||
        kernel_get_ucred_authid(self) != original_authid) {
        error = EIO; goto done;
    }
    auth_restored = 1;
    auth_changed = 0;
    stage = "child_exit";
    if (write(release[1], "G", 1) != 1) { error = EPIPE; goto done; }
    error = wait_exit(child, &reaped);
    if (error) goto done;
    stage = "complete";
done:
    if (attached && !stopped && !reaped) {
        ps5log_printf(PS5LOG_ERR,
                      "probe_held build=%s stage=%s error=%d stopped=%d modified=%d",
                      LAPY_PROBE_ID, stage, error, stopped, modified);
        for (;;) sleep(1);
    }
    if (attached && stopped && !reaped) {
        if (regs_saved && !regs_restored) {
            if (ptrace_set(child, &original) ||
                ptrace_get(child, &restored) ||
                memcmp(&restored, &original, sizeof(original))) {
                ps5log_printf(PS5LOG_ERR,
                              "probe_held build=%s stage=%s error=%d reason=restore_failed",
                              LAPY_PROBE_ID, stage, error);
                for (;;) sleep(1);
            }
            regs_restored = 1;
        }
        if (!ptrace(PT_DETACH, child, (caddr_t)1, 0)) {
            detached = 1;
            attached = 0;
        } else {
            ps5log_printf(PS5LOG_ERR,
                          "probe_held build=%s stage=%s error=%d reason=detach_failed",
                          LAPY_PROBE_ID, stage, error);
            for (;;) sleep(1);
        }
    }
    if (auth_changed &&
        !kernel_set_ucred_authid(self, original_authid) &&
        kernel_get_ucred_authid(self) == original_authid)
        auth_restored = 1;
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
                  "probe_result build=%s stage=%s error=%d attached=%d detached=%d cloned=%d registers_restored=%d auth_restored=%d reaped=%d",
                  LAPY_PROBE_ID, stage, error, attached, detached, cloned,
                  regs_restored, auth_restored, reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
