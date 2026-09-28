/* Controlled donor exchange of a natively acquired non-system root.
 * Only verified filedesc directory slots are written. Firmware 12.02 only. */
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
#define CANDIDATE_CDIR 0x08u
#define WAIT_MS 5000
#define CHILD_ALARM 12
#define SETTLE_US 20000

struct donor {
    pid_t pid;
    int ready[2], go[2];
    intptr_t filedesc, cdir;
    int reaped;
};

static int read_ptr(intptr_t address, intptr_t *value)
{
    return kernel_copyout(address, value, sizeof(*value)) ? EFAULT : 0;
}

static int write_ptr(intptr_t address, intptr_t value)
{
    intptr_t observed = 0;
    if (kernel_copyin(&value, address, sizeof(value)) ||
        read_ptr(address, &observed) || observed != value) return EFAULT;
    return 0;
}

static int get_root(intptr_t *root)
{
    *root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (*root) return 0;
    intptr_t init_fd = kernel_get_proc_filedesc(1);
    if (!init_fd || read_ptr(init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                              root) || !*root) return ENOTSUP;
    return 0;
}

static int sample(intptr_t root, intptr_t data, const char *phase,
                  uint32_t *root_hold, uint32_t *root_use,
                  uint32_t *data_hold, uint32_t *data_use)
{
    if (kernel_copyout(root + HINT_HOLD, root_hold, sizeof(*root_hold)) ||
        kernel_copyout(root + HINT_USE, root_use, sizeof(*root_use)))
        return EFAULT;
    if (data &&
        (kernel_copyout(data + HINT_HOLD, data_hold, sizeof(*data_hold)) ||
         kernel_copyout(data + HINT_USE, data_use, sizeof(*data_use))))
        return EFAULT;
    ps5log_printf(PS5LOG_MARK,
                  "old_root_sample build=%s phase=%s root_hold=%u root_use=%u data_known=%d data_hold=%u data_use=%u",
                  LAPY_PROBE_ID, phase, *root_hold, *root_use, data != 0,
                  data ? *data_hold : 0, data ? *data_use : 0);
    return 0;
}

static void child_main(struct donor *self, const struct donor *other,
                       int chdir_data)
{
    char go = 0;
    close(self->ready[0]);
    close(self->go[1]);
    if (other) {
        if (other->ready[0] >= 0) close(other->ready[0]);
        if (other->go[1] >= 0) close(other->go[1]);
    }
    alarm(CHILD_ALARM);
    if (chdir_data && chdir("/data")) _exit(2);
    if (write(self->ready[1], "R", 1) != 1) _exit(3);
    if (read(self->go[0], &go, 1) != 1 || go != 'G') _exit(4);
    close(self->ready[1]);
    close(self->go[0]);
    _exit(0);
}

static int ready_byte(int fd)
{
    struct pollfd ready = {fd, POLLIN, 0};
    char value = 0;
    int status = poll(&ready, 1, WAIT_MS);
    if (status <= 0) return status < 0 ? errno : ETIMEDOUT;
    return read(fd, &value, 1) == 1 && value == 'R' ? 0 : EPROTO;
}

static int start_donor(struct donor *donor, const struct donor *other,
                       intptr_t root, int chdir_data)
{
    intptr_t rdir = 0, jdir = 0;
    uint32_t ref_hint = 0;
    if (pipe(donor->ready) || pipe(donor->go)) return errno ? errno : EIO;
    donor->pid = rfork(RFPROC | RFFDG);
    if (donor->pid == 0) child_main(donor, other, chdir_data);
    if (donor->pid < 0) return errno ? errno : EIO;
    close(donor->ready[1]); donor->ready[1] = -1;
    close(donor->go[0]); donor->go[0] = -1;
    int error = ready_byte(donor->ready[0]);
    if (error) return error;
    donor->filedesc = kernel_get_proc_filedesc(donor->pid);
    if (!donor->filedesc ||
        read_ptr(donor->filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR, &rdir) ||
        read_ptr(donor->filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR, &jdir) ||
        read_ptr(donor->filedesc + CANDIDATE_CDIR, &donor->cdir) ||
        kernel_copyout(donor->filedesc + 0x34, &ref_hint,
                       sizeof(ref_hint))) return EFAULT;
    if (rdir != root || jdir != 0 || ref_hint != 1 || !donor->cdir ||
        (chdir_data ? donor->cdir == root : donor->cdir != root))
        return EPROTO;
    ps5log_printf(PS5LOG_MARK,
                  "donor_ready build=%s role=%s private=1 root_system=1 jail_null=1 cdir_system=%d ref_hint=%u",
                  LAPY_PROBE_ID, chdir_data ? "old" : "replacement",
                  donor->cdir == root, ref_hint);
    return 0;
}

static int exit_donor(struct donor *donor)
{
    int status = 0;
    if (write(donor->go[1], "G", 1) != 1) return EPIPE;
    for (unsigned i = 0; i < 50; ++i) {
        pid_t result = waitpid(donor->pid, &status, WNOHANG);
        if (result == donor->pid) {
            donor->reaped = 1;
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : EPROTO;
        }
        if (result < 0) return errno ? errno : ECHILD;
        usleep(100000);
    }
    kill(donor->pid, SIGKILL);
    donor->reaped = waitpid(donor->pid, &status, 0) == donor->pid;
    return ETIMEDOUT;
}

static void cleanup_donor(struct donor *donor)
{
    if (donor->pid > 0 && !donor->reaped) {
        kill(donor->pid, SIGKILL);
        waitpid(donor->pid, 0, 0);
        donor->reaped = 1;
    }
    if (donor->ready[0] >= 0) close(donor->ready[0]);
    if (donor->ready[1] >= 0) close(donor->ready[1]);
    if (donor->go[0] >= 0) close(donor->go[0]);
    if (donor->go[1] >= 0) close(donor->go[1]);
}

/* Exchange two already owned references in private blocked filedescs. Put
 * root in the first slot to create only a transient extra root ownership,
 * never a transient null process root or extra /data ownership. */
static int exchange(intptr_t source_slot, intptr_t dest_slot,
                    intptr_t expected_source, intptr_t expected_dest,
                    int dest_first)
{
    intptr_t source = 0, dest = 0;
    if (read_ptr(source_slot, &source) || read_ptr(dest_slot, &dest) ||
        source != expected_source || dest != expected_dest) return EPROTO;
    if (dest_first) {
        if (write_ptr(dest_slot, expected_source)) return EFAULT;
        if (write_ptr(source_slot, expected_dest)) {
            if (!read_ptr(source_slot, &source) && source == expected_source)
                write_ptr(dest_slot, expected_dest);
            return EFAULT;
        }
    } else {
        if (write_ptr(source_slot, expected_dest)) return EFAULT;
        if (write_ptr(dest_slot, expected_source)) {
            if (!read_ptr(dest_slot, &dest) && dest == expected_dest)
                write_ptr(source_slot, expected_source);
            return EFAULT;
        }
    }
    return 0;
}

int main(void)
{
    struct donor old = {.pid = -1, .ready = {-1, -1}, .go = {-1, -1}};
    struct donor replacement = {.pid = -1, .ready = {-1, -1}, .go = {-1, -1}};
    intptr_t root = 0, target_fd = 0, target_root = 0, target_jail = 0;
    intptr_t target_cdir = 0, data = 0;
    uint32_t ref_hint = 0, rh = 0, ru = 0, dh = 0, du = 0;
    int error = 0;
    const char *stage = "preflight";

    if (ps5log_init_default("LAPYOLD", "lapy-old-root-release-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=donor-old-root-release",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    if (kernel_get_fw_version() != 0x12020000 ||
        !KERNEL_OFFSET_FILEDESC_FD_RDIR ||
        !KERNEL_OFFSET_FILEDESC_FD_JDIR) {
        error = ENOTSUP;
        goto done;
    }
    if ((error = get_root(&root))) goto done;
    target_fd = kernel_get_proc_filedesc(getpid());
    if (!target_fd ||
        read_ptr(target_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, &target_root) ||
        read_ptr(target_fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, &target_jail) ||
        read_ptr(target_fd + CANDIDATE_CDIR, &target_cdir) ||
        kernel_copyout(target_fd + 0x34, &ref_hint, sizeof(ref_hint))) {
        error = EFAULT;
        goto done;
    }
    if (target_root != root || target_cdir != root || target_jail ||
        ref_hint != 1) {
        error = EPROTO;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "target_ready build=%s private=1 root_system=1 jail_null=1 cdir_system=1 ref_hint=%u",
                  LAPY_PROBE_ID, ref_hint);
    stage = "baseline";
    if ((error = sample(root, 0, "baseline", &rh, &ru, &dh, &du))) goto done;
    stage = "old_donor";
    if ((error = start_donor(&old, 0, root, 1))) goto done;
    data = old.cdir;
    usleep(SETTLE_US);
    stage = "data_acquired";
    if ((error = sample(root, data, "data_acquired", &rh, &ru,
                        &dh, &du))) goto done;
    stage = "replacement_donor";
    if ((error = start_donor(&replacement, &old, root, 0))) goto done;
    usleep(SETTLE_US);
    stage = "both_held";
    if ((error = sample(root, data, "both_held", &rh, &ru,
                        &dh, &du))) goto done;
    stage = "place_old_root";
    if ((error = exchange(old.filedesc + CANDIDATE_CDIR,
                          target_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                          data, root, 0))) goto done;
    if ((error = sample(root, data, "old_root_placed", &rh, &ru,
                        &dh, &du))) goto done;
    stage = "old_donor_exit";
    if ((error = exit_donor(&old))) goto done;
    usleep(SETTLE_US);
    if ((error = sample(root, data, "old_donor_released", &rh, &ru,
                        &dh, &du))) goto done;
    stage = "restore_root";
    if ((error = exchange(replacement.filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                          target_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                          root, data, 1))) goto done;
    if ((error = sample(root, data, "root_restored", &rh, &ru,
                        &dh, &du))) goto done;
    stage = "replacement_exit";
    if ((error = exit_donor(&replacement))) goto done;
    usleep(SETTLE_US);
    stage = "baseline_restored";
    if ((error = sample(root, data, "baseline_restored", &rh, &ru,
                        &dh, &du))) goto done;
    stage = "complete";
done:
    cleanup_donor(&old);
    cleanup_donor(&replacement);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d old_reaped=%d replacement_reaped=%d",
                  LAPY_PROBE_ID, stage, error, old.reaped,
                  replacement.reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
