/* Adopt a different root using native calls, retaining its jaildir reference.
 * Operates on this payload only. No credential writes or file creation. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include "native_vfs_syscall.h"
#include <errno.h>
#include <fcntl.h>
#include <ps5/kernel.h>
#include <sys/stat.h>
#include <unistd.h>

static int directories(intptr_t *root, intptr_t *jail)
{
    intptr_t fd = kernel_get_proc_filedesc(getpid());
    if (!fd || kernel_copyout(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, root, sizeof(*root)) ||
        kernel_copyout(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, jail, sizeof(*jail)))
        return EFAULT;
    return 0;
}

int main(void)
{
    int root = -1, cwd = -1, error = 0, restore_error = 0, changed = 0;
    int jail_preserved = 0, data_access = 0, sandbox_established = 0;
    intptr_t sandbox_root = 0, sandbox_jail = 0, final_root = 0, final_jail = 0;
    struct stat original, current, data_before, data_after, cwd_before, cwd_after;
    const char *stage = "prepare";
    if (ps5log_init_default("LAPYROOT", "lapy-cross-root-probe")) return 2;
    ps5log_printf(PS5LOG_MARK, "probe_start build=%s firmware=%08x mode=cross-root",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) { error = errno; goto done; }
    cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cwd < 0) { error = errno; goto done; }
    if (fstat(root, &original) || fstat(cwd, &cwd_before) || stat("/data", &data_before)) {
        error = errno; goto done;
    }
    stage = "sandbox_chroot";
    ps5log_printf(PS5LOG_MARK, "probe_operation stage=%s", stage);
    if ((error = lapy_vfs_chroot("/data"))) goto done;
    changed = 1;
    if (chdir("/") < 0) { error = errno; goto done; }
    stage = "sandbox_identity";
    if (stat("/", &current) < 0) { error = errno; goto done; }
    if (current.st_dev != data_before.st_dev || current.st_ino != data_before.st_ino) {
        error = EPROTO; goto done;
    }
    if ((error = directories(&sandbox_root, &sandbox_jail))) goto done;
    /* Require an actual jail directory equal to the temporary sandbox root.
     * If the loader already supplies another jaildir, this gate is inconclusive. */
    if (!sandbox_root || sandbox_jail != sandbox_root) { error = ENOTSUP; goto done; }
    sandbox_established = 1;
    stage = "adopt_root";
    ps5log_printf(PS5LOG_MARK, "probe_operation stage=%s", stage);
    if ((error = lapy_vfs_fchdir(root)) || (error = lapy_vfs_chroot("."))) goto done;
    stage = "adopted_identity";
    if (stat("/", &current) < 0) { error = errno; goto done; }
    if (current.st_dev != original.st_dev || current.st_ino != original.st_ino) {
        error = EPROTO; goto done;
    }
    if ((error = directories(&final_root, &final_jail))) goto done;
    if (!final_root || final_root == sandbox_root || final_jail != sandbox_jail) {
        error = EPROTO; goto done;
    }
    jail_preserved = 1;
    stage = "data_access";
    if (stat("/data", &data_after) < 0) { error = errno; goto done; }
    if (data_after.st_dev != data_before.st_dev || data_after.st_ino != data_before.st_ino) {
        error = EPROTO; goto done;
    }
    data_access = 1;
    stage = "complete";
done:
    if (changed) {
        /* Only native operations: restore the effective root and working
         * directory even after a failed gate. Never overwrite jaildir. */
        restore_error = lapy_vfs_fchdir(root);
        if (!restore_error) restore_error = lapy_vfs_chroot(".");
        if (!restore_error) restore_error = lapy_vfs_fchdir(cwd);
        if (!restore_error && (stat("/", &current) < 0 || stat(".", &cwd_after) < 0))
            restore_error = errno;
        else if (!restore_error && (current.st_dev != original.st_dev || current.st_ino != original.st_ino ||
                 cwd_after.st_dev != cwd_before.st_dev || cwd_after.st_ino != cwd_before.st_ino))
            restore_error = EPROTO;
    }
    if (cwd >= 0) close(cwd);
    if (root >= 0) close(root);
    ps5log_printf(error || restore_error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d restore_error=%d sandbox=%d jail_preserved=%d data_access=%d",
                  LAPY_PROBE_ID, stage, error, restore_error,
                  sandbox_established, jail_preserved, data_access);
    ps5log_close(error || restore_error ? "probe-failed" : "probe-complete");
    return error || restore_error ? 1 : 0;
}
