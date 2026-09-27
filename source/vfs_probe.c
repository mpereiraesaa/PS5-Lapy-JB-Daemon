/* Native VFS capability gate on the payload's existing root. No privilege
 * elevation, raw kernel writes, children or target title operations. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include "native_vfs_syscall.h"
#include <errno.h>
#include <fcntl.h>
#include <ps5/kernel.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    int root = -1, cwd = -1, error = 0, restore_error = 0;
    unsigned complete = 0;
    int cwd_changed = 0;
    const char *stage = "open_cwd";
    struct stat original, current, old_cwd, restored;
    if (ps5log_init_default("LAPYVFS", "lapy-vfs-probe")) return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x cycles=1 mode=existing-root",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cwd < 0) { error = errno; goto done; }
    if (fstat(cwd, &old_cwd) < 0) { error = errno; goto done; }
    stage = "open_root";
    root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) { error = errno; goto done; }
    if (fstat(root, &original) < 0) { error = errno; goto done; }
    stage = "native_fchdir";
    ps5log_printf(PS5LOG_MARK, "probe_operation stage=%s", stage);
    if ((error = lapy_vfs_fchdir(root))) goto done;
    cwd_changed = 1;
    stage = "native_chroot";
    ps5log_printf(PS5LOG_MARK, "probe_operation stage=%s", stage);
    if ((error = lapy_vfs_chroot("."))) goto done;
    stage = "root_identity";
    if (stat("/", &current) < 0) { error = errno; goto done; }
    if (original.st_dev != current.st_dev || original.st_ino != current.st_ino) {
        error = EPROTO; goto done;
    }
    complete = 1;
    stage = "complete";
done:
    if (cwd >= 0) {
        if (cwd_changed) {
            restore_error = lapy_vfs_fchdir(cwd);
            if (!restore_error && stat(".", &restored) < 0) restore_error = errno;
            else if (!restore_error && (old_cwd.st_dev != restored.st_dev || old_cwd.st_ino != restored.st_ino))
                restore_error = EPROTO;
        }
        close(cwd);
    }
    if (root >= 0) close(root);
    ps5log_printf(error || restore_error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d restore_error=%d completed=%u expected=1",
                  LAPY_PROBE_ID, stage, error, restore_error, complete);
    ps5log_close(error || restore_error ? "probe-failed" : "probe-complete");
    return error || restore_error ? 1 : 0;
}
