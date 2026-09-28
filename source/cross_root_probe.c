/* Adopt a different root using native calls, retaining its jaildir reference.
 * Operates on this payload only. Native identity and Sony-field changes are
 * explicit optional modes; no raw root/prison writes or file creation. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include "native_vfs_syscall.h"
#include "vfs_prerequisites.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <ps5/kernel.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sony_scope.h"

#ifndef LAPY_PROBE_SONY
#define LAPY_PROBE_SONY 0
#endif
#ifndef LAPY_PROBE_ROOT_IDENTITY
#define LAPY_PROBE_ROOT_IDENTITY 0
#endif
#ifndef LAPY_PROBE_CWD_ROOT
#define LAPY_PROBE_CWD_ROOT 0
#endif

#if LAPY_PROBE_SONY
static uintptr_t current_credential(void *unused)
{
    (void)unused;
    return (uintptr_t)kernel_get_proc_ucred(getpid());
}
static int clone_credential(void *unused)
{
    (void)unused;
    return seteuid(geteuid()) < 0 ? errno : 0;
}
static int read_sony(void *unused, uintptr_t id, struct lapy_sony_fields *f)
{
    if (current_credential(unused) != id) return ESTALE;
    return kernel_copyout(id + KERNEL_OFFSET_UCRED_CR_SCEAUTHID, &f->authority, sizeof(f->authority)) ||
           kernel_copyout(id + KERNEL_OFFSET_UCRED_CR_SCECAPS, f->caps, sizeof(f->caps)) ? EFAULT : 0;
}
static int write_sony(void *unused, uintptr_t id, const struct lapy_sony_fields *f)
{
    if (current_credential(unused) != id) return ESTALE;
    return kernel_copyin(&f->authority, id + KERNEL_OFFSET_UCRED_CR_SCEAUTHID, sizeof(f->authority)) ||
           kernel_copyin(f->caps, id + KERNEL_OFFSET_UCRED_CR_SCECAPS, sizeof(f->caps)) ? EFAULT : 0;
}
#endif

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
    int sony_restore_error = 0;
    int cwd_changed = 0;
    char saved_cwd[PATH_MAX];
#if LAPY_PROBE_SONY
    struct lapy_sony_scope sony = {0};
    const struct lapy_sony_ops sony_ops = {NULL, current_credential, clone_credential, read_sony, write_sony};
#endif
    intptr_t sandbox_root = 0, sandbox_jail = 0, final_root = 0, final_jail = 0;
    struct stat original, current, data_before, data_after, cwd_before, cwd_after;
    const char *stage = "prepare";
    if (ps5log_init_default("LAPYROOT", "lapy-cross-root-probe")) return 2;
    ps5log_printf(PS5LOG_MARK, "probe_start build=%s firmware=%08x mode=cross-root sony_scope=%d root_identity=%d cwd_root=%d",
                  LAPY_PROBE_ID, kernel_get_fw_version(), LAPY_PROBE_SONY, LAPY_PROBE_ROOT_IDENTITY, LAPY_PROBE_CWD_ROOT);
    stage = "prerequisites";
    if ((error = log_vfs_prerequisites())) goto done;
#if LAPY_PROBE_ROOT_IDENTITY
    /* Native identity accounting; never overwrite cr_uid or uidinfo pointers.
     * This disposable payload retains the native identity until it exits. */
    stage = "native_setgid";
    if ((error = lapy_vfs_syscall(SYS_setgid, 0))) goto done;
    stage = "native_setuid";
    if ((error = lapy_vfs_syscall(SYS_setuid, 0))) goto done;
    stage = "native_identity_readback";
    if (getuid() || geteuid() || getgid() || getegid() || kernel_get_ucred_svuid(getpid())) {
        error = EPROTO; goto done;
    }
    ps5log_printf(PS5LOG_MARK, "native_identity root_uid=1 root_gid=1 saved_uid_root=1");
#endif
#if LAPY_PROBE_SONY
    stage = "sony_scope_begin";
    struct lapy_sony_fields desired = {.authority = UINT64_C(0x4801000000000013)};
    memset(desired.caps, 0xff, sizeof(desired.caps));
    if ((error = lapy_sony_scope_begin(&sony, &sony_ops, &desired))) goto done;
    ps5log_printf(PS5LOG_MARK, "sony_scope active=1 credential_replaced=1");
    if ((error = log_vfs_prerequisites())) goto done;
#endif
    stage = "fchdir_negative_control";
    error = lapy_vfs_fchdir(-1);
    ps5log_printf(PS5LOG_MARK, "vfs_negative_control actual=%d expected=%d", error, EBADF);
    if (error != EBADF) { if (!error) error = EPROTO; goto done; }
    error = 0;
    stage = "prepare";
    if (LAPY_PROBE_CWD_ROOT) {
        if (!getcwd(saved_cwd, sizeof(saved_cwd)) || stat(".", &cwd_before) ||
            stat("/", &original) || stat("/data", &data_before)) {
            error = errno; goto done;
        }
        if (chdir("/") < 0) { error = errno; goto done; }
        cwd_changed = 1;
    } else {
    root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) { error = errno; goto done; }
    cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cwd < 0) { error = errno; goto done; }
    if (fstat(root, &original) || fstat(cwd, &cwd_before) || stat("/data", &data_before)) {
        error = errno; goto done;
    }
    }
    stage = "directory_fd_inventory";
    if ((error = log_directory_fd_inventory())) goto done;
    stage = "sandbox_chroot";
    ps5log_printf(PS5LOG_MARK, "probe_operation stage=%s", stage);
    if ((error = lapy_vfs_chroot("/data"))) goto done;
    changed = 1;
    if (!LAPY_PROBE_CWD_ROOT && chdir("/") < 0) { error = errno; goto done; }
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
    if (!LAPY_PROBE_CWD_ROOT && (error = lapy_vfs_fchdir(root))) goto done;
    if ((error = lapy_vfs_chroot("."))) goto done;
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
        restore_error = LAPY_PROBE_CWD_ROOT ? 0 : lapy_vfs_fchdir(root);
        if (!restore_error) restore_error = lapy_vfs_chroot(".");
        if (!restore_error) restore_error = LAPY_PROBE_CWD_ROOT ?
            (chdir(saved_cwd) < 0 ? errno : 0) : lapy_vfs_fchdir(cwd);
        cwd_changed = 0;
        if (!restore_error && (stat("/", &current) < 0 || stat(".", &cwd_after) < 0))
            restore_error = errno;
        else if (!restore_error && (current.st_dev != original.st_dev || current.st_ino != original.st_ino ||
                 cwd_after.st_dev != cwd_before.st_dev || cwd_after.st_ino != cwd_before.st_ino))
            restore_error = EPROTO;
    }
    if (cwd_changed && chdir(saved_cwd) < 0) restore_error = errno;
    if (cwd >= 0) close(cwd);
    if (root >= 0) close(root);
#if LAPY_PROBE_SONY
    sony_restore_error = lapy_sony_scope_end(&sony, &sony_ops);
#endif
    ps5log_printf(error || restore_error || sony_restore_error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d restore_error=%d sony_restore_error=%d sandbox=%d jail_preserved=%d data_access=%d",
                  LAPY_PROBE_ID, stage, error, restore_error, sony_restore_error,
                  sandbox_established, jail_preserved, data_access);
    ps5log_close(error || restore_error || sony_restore_error ? "probe-failed" : "probe-complete");
    return error || restore_error || sony_restore_error ? 1 : 0;
}
