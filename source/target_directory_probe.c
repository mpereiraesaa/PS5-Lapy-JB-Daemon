/* One-shot, read-only directory-state observation for a specified target PID.
 * Pointers remain private to this payload; telemetry contains booleans only.
 * A stable snapshot does not retain the process or prove lifetime safety. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <unistd.h>

#ifndef LAPY_TARGET_PID
#error "Build with --target-pid for this read-only probe"
#endif

struct snapshot {
    intptr_t filedesc, root, jail;
};

static int snapshot(pid_t pid, struct snapshot *out)
{
    out->filedesc = kernel_get_proc_filedesc(pid);
    if (!out->filedesc) return ESRCH;
    if (kernel_copyout(out->filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                       &out->root, sizeof(out->root)) ||
        kernel_copyout(out->filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                       &out->jail, sizeof(out->jail))) return EFAULT;
    return out->root ? 0 : EPROTO;
}

int main(void)
{
    const pid_t pid = LAPY_TARGET_PID;
    struct snapshot first = {0}, second = {0};
    intptr_t system_root = 0;
    const char *stage = "first_snapshot";
    int error = 0;

    if (ps5log_init_default("LAPYDIR", "lapy-target-directory-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x target_pid=%d mode=read-only",
                  LAPY_PROBE_ID, kernel_get_fw_version(), (int)pid);
    if (pid <= 1 || pid == getpid()) { error = EINVAL; goto done; }
    error = snapshot(pid, &first);
    if (error) goto done;
    usleep(10000);
    stage = "second_snapshot";
    error = snapshot(pid, &second);
    if (error) goto done;
    stage = "stability";
    if (first.filedesc != second.filedesc || first.root != second.root ||
        first.jail != second.jail) { error = ESTALE; goto done; }

    /* The SDK may omit the per-firmware rootvnode symbol. Its absence only
     * removes the system-root comparison, not the null/equality observation. */
    if (KERNEL_ADDRESS_ROOTVNODE) system_root = kernel_get_root_vnode();
    stage = "complete";
done:
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s target_pid=%d stage=%s error=%d stable=%d root_nonnull=%d jail_nonnull=%d root_jail_same=%d system_known=%d root_system=%d jail_system=%d",
                  LAPY_PROBE_ID, (int)pid, stage, error,
                  !error, !error && second.root != 0,
                  !error && second.jail != 0,
                  !error && second.root == second.jail,
                  !error && system_root != 0,
                  !error && system_root != 0 && second.root == system_root,
                  !error && system_root != 0 && second.jail == system_root);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
