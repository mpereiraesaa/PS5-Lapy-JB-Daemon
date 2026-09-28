/* Observe root-vnode field changes caused by ordinary open/close. This probe
 * only reads kernel memory; it does not elevate or write kernel structures. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <unistd.h>

#define ROOT_FDS 4
#define HINT_HOLD 0x1bcu
#define HINT_USE 0x1c0u
#define SETTLE_US 20000u

static int read_pointer(intptr_t address, intptr_t *value)
{
    return kernel_copyout(address, value, sizeof(*value)) ? EFAULT : 0;
}

static int get_root(intptr_t *root)
{
    *root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (*root) return 0;
    intptr_t init_fd = kernel_get_proc_filedesc(1);
    if (!init_fd) return ENOTSUP;
    if (read_pointer(init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, root))
        return EFAULT;
    return *root ? 0 : ENOTSUP;
}

static int sample(intptr_t root, const char *phase, unsigned step,
                  uint32_t *hold, uint32_t *use)
{
    if (kernel_copyout(root + HINT_HOLD, hold, sizeof(*hold)) ||
        kernel_copyout(root + HINT_USE, use, sizeof(*use)))
        return EFAULT;
    ps5log_printf(PS5LOG_MARK,
                  "native_sample build=%s phase=%s step=%u hold_offset=0x%x hold=%u use_offset=0x%x use=%u",
                  LAPY_PROBE_ID, phase, step, HINT_HOLD, *hold,
                  HINT_USE, *use);
    return 0;
}

int main(void)
{
    intptr_t root = 0, self_fd = 0, rdir = 0, jdir = 0;
    int fds[ROOT_FDS] = {-1, -1, -1, -1};
    int error = 0, cleanup_error = 0;
    uint32_t hold = 0, use = 0;
    const char *stage = "root";

    if (ps5log_init_default("LAPYOWN", "lapy-native-root-reference-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=native-open-close count=%u",
                  LAPY_PROBE_ID, kernel_get_fw_version(), ROOT_FDS);
    error = get_root(&root);
    if (error) goto done;
    stage = "own_filedesc";
    self_fd = kernel_get_proc_filedesc(getpid());
    if (!self_fd) { error = ESRCH; goto done; }
    if ((error = read_pointer(self_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                              &rdir)) ||
        (error = read_pointer(self_fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                              &jdir))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "directory_identity build=%s root_null=%d root_system=%d jail_null=%d jail_system=%d",
                  LAPY_PROBE_ID, rdir == 0, rdir == root,
                  jdir == 0, jdir == root);
    /* With another root or jail, opening '/' cannot calibrate rootvnode. */
    if ((rdir && rdir != root) || (jdir && jdir != root)) {
        error = ENOTSUP;
        goto done;
    }
    stage = "baseline";
    if ((error = sample(root, "baseline", 0, &hold, &use))) goto done;
    if (!hold || !use || hold > 4096 || use > 4096) {
        error = EPROTO;
        goto done;
    }
    for (unsigned i = 0; i < ROOT_FDS; ++i) {
        stage = "open";
        fds[i] = open("/", O_RDONLY | O_DIRECTORY);
        if (fds[i] < 0) { error = errno ? errno : EIO; goto done; }
        usleep(SETTLE_US);
        if ((error = sample(root, "held", i + 1, &hold, &use))) goto done;
    }
    for (unsigned i = 0; i < ROOT_FDS; ++i) {
        stage = "close";
        if (close(fds[i])) { error = errno ? errno : EIO; goto done; }
        fds[i] = -1;
        usleep(SETTLE_US);
        if ((error = sample(root, "released", i + 1,
                            &hold, &use))) goto done;
    }
    stage = "complete";
done:
    for (unsigned i = 0; i < ROOT_FDS; ++i) {
        if (fds[i] >= 0 && close(fds[i]) && !cleanup_error)
            cleanup_error = errno ? errno : EIO;
    }
    if (!error) error = cleanup_error;
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d cleanup_error=%d",
                  LAPY_PROBE_ID, stage, error, cleanup_error);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
