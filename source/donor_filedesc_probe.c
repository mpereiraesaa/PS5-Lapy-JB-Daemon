/* Measure root-vnode references acquired and released by a native
 * RFPROC|RFFDG filedesc donor. This probe only reads kernel memory. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#define HINT_HOLD 0x1bcu
#define HINT_USE 0x1c0u
#define CHILD_ALARM 10
#define WAIT_MS 5000
#define SETTLE_US 20000

struct child_report {
    uint8_t distinct_fd, root_system, jail_null, cdir_system;
    uint32_t ref_hint;
};

static int read_pointer(intptr_t address, intptr_t *value)
{
    return kernel_copyout(address, value, sizeof(*value)) ? EFAULT : 0;
}

static int get_root(intptr_t *root)
{
    *root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (*root) return 0;
    intptr_t init_fd = kernel_get_proc_filedesc(1);
    if (!init_fd || read_pointer(init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                                 root) || !*root) return ENOTSUP;
    return 0;
}

static int sample(intptr_t root, const char *phase,
                  uint32_t *hold, uint32_t *use)
{
    if (kernel_copyout(root + HINT_HOLD, hold, sizeof(*hold)) ||
        kernel_copyout(root + HINT_USE, use, sizeof(*use)))
        return EFAULT;
    ps5log_printf(PS5LOG_MARK,
                  "donor_sample build=%s phase=%s hold=%u use=%u",
                  LAPY_PROBE_ID, phase, *hold, *use);
    return 0;
}

static void child_main(int ready[2], int go[2], intptr_t parent_fd,
                       intptr_t system_root)
{
    struct child_report report = {0};
    intptr_t fd = 0, root = 0, jail = 0, cdir = 0;
    char signal_byte = 0;
    close(ready[0]);
    close(go[1]);
    alarm(CHILD_ALARM);
    fd = kernel_get_proc_filedesc(getpid());
    if (!fd ||
        read_pointer(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, &root) ||
        read_pointer(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, &jail) ||
        read_pointer(fd + 0x08, &cdir) ||
        kernel_copyout(fd + 0x34, &report.ref_hint,
                       sizeof(report.ref_hint))) _exit(2);
    report.distinct_fd = fd != parent_fd;
    report.root_system = root == system_root;
    report.jail_null = jail == 0;
    report.cdir_system = cdir == system_root;
    if (write(ready[1], &report, sizeof(report)) != sizeof(report)) _exit(3);
    if (read(go[0], &signal_byte, 1) != 1 || signal_byte != 'G') _exit(4);
    close(ready[1]);
    close(go[0]);
    _exit(0);
}

static int read_report(int fd, struct child_report *report)
{
    struct pollfd pollfd = {fd, POLLIN, 0};
    int ready = poll(&pollfd, 1, WAIT_MS);
    if (ready <= 0) return ready < 0 ? errno : ETIMEDOUT;
    return read(fd, report, sizeof(*report)) == sizeof(*report) ? 0 : EPIPE;
}

static int reap_child(pid_t child, int *status)
{
    for (unsigned i = 0; i < 50; ++i) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 0;
        if (result < 0) return errno ? errno : ECHILD;
        usleep(100000);
    }
    kill(child, SIGKILL);
    return waitpid(child, status, 0) == child ? ETIMEDOUT : ECHILD;
}

int main(void)
{
    int ready[2] = {-1, -1}, go[2] = {-1, -1};
    intptr_t root = 0, parent_fd = 0, parent_root = 0, parent_jail = 0;
    uint32_t hold = 0, use = 0;
    struct child_report report = {0};
    pid_t child = -1;
    int error = 0, cleanup_error = 0, status = 0, reaped = 0;
    const char *stage = "root";

    if (ps5log_init_default("LAPYDON", "lapy-donor-filedesc-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=donor-rfork-read-only",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    if (kernel_get_fw_version() != 0x12020000) {
        error = ENOTSUP;
        goto done;
    }
    if ((error = get_root(&root))) goto done;
    stage = "parent";
    parent_fd = kernel_get_proc_filedesc(getpid());
    if (!parent_fd ||
        (error = read_pointer(parent_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                              &parent_root)) ||
        (error = read_pointer(parent_fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                              &parent_jail))) {
        if (!error) error = ESRCH;
        goto done;
    }
    if (parent_root != root || parent_jail) {
        error = ENOTSUP;
        goto done;
    }
    stage = "pipes";
    if (pipe(ready) || pipe(go)) {
        error = errno ? errno : EIO;
        goto done;
    }
    stage = "baseline";
    if ((error = sample(root, "baseline", &hold, &use))) goto done;
    stage = "rfork";
    child = rfork(RFPROC | RFFDG);
    if (child == 0) child_main(ready, go, parent_fd, root);
    if (child < 0) {
        error = errno ? errno : EIO;
        goto done;
    }
    close(ready[1]); ready[1] = -1;
    close(go[0]); go[0] = -1;
    stage = "child_ready";
    if ((error = read_report(ready[0], &report))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "donor_identity build=%s distinct_fd=%u root_system=%u jail_null=%u cdir_system=%u ref_hint=%u",
                  LAPY_PROBE_ID, report.distinct_fd, report.root_system,
                  report.jail_null, report.cdir_system, report.ref_hint);
    usleep(SETTLE_US);
    stage = "held";
    if ((error = sample(root, "held", &hold, &use))) goto done;
    if (write(go[1], "G", 1) != 1) {
        error = EPIPE;
        goto done;
    }
    stage = "reap";
    error = reap_child(child, &status);
    reaped = 1;
    if (error) goto done;
    usleep(SETTLE_US);
    stage = "released";
    if ((error = sample(root, "released", &hold, &use))) goto done;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        error = EPROTO;
        goto done;
    }
    stage = "complete";
done:
    if (go[1] >= 0) close(go[1]);
    if (go[0] >= 0) close(go[0]);
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (child > 0 && !reaped) {
        kill(child, SIGKILL);
        if (waitpid(child, &status, 0) != child) cleanup_error = ECHILD;
    }
    if (!error) error = cleanup_error;
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d cleanup_error=%d child_reaped=%d",
                  LAPY_PROBE_ID, stage, error, cleanup_error,
                  child <= 0 || reaped || !cleanup_error);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
