/* One-shot reference-token transfer between private disposable filedescs.
 * This writes ONLY the verified null jail and donor directory slots, never
 * vnode counters or a game/launcher process. Firmware 12.02 only. */
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
#define WAIT_MS 5000
#define CHILD_ALARM 12
#define SETTLE_US 20000

struct donor {
    pid_t pid;
    int ready[2], go[2];
    intptr_t filedesc;
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

static int sample(intptr_t root, const char *phase,
                  uint32_t *hold, uint32_t *use)
{
    if (kernel_copyout(root + HINT_HOLD, hold, sizeof(*hold)) ||
        kernel_copyout(root + HINT_USE, use, sizeof(*use))) return EFAULT;
    ps5log_printf(PS5LOG_MARK,
                  "transfer_sample build=%s phase=%s hold=%u use=%u",
                  LAPY_PROBE_ID, phase, *hold, *use);
    return 0;
}

static void donor_child(struct donor *self, const struct donor *other)
{
    char go = 0;
    close(self->ready[0]);
    close(self->go[1]);
    if (other) {
        if (other->ready[0] >= 0) close(other->ready[0]);
        if (other->go[1] >= 0) close(other->go[1]);
    }
    alarm(CHILD_ALARM);
    if (write(self->ready[1], "R", 1) != 1) _exit(2);
    if (read(self->go[0], &go, 1) != 1 || go != 'G') _exit(3);
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
                       intptr_t root, int is_receiver)
{
    intptr_t rdir = 0, jdir = 0;
    uint32_t ref_hint = 0;
    if (pipe(donor->ready) || pipe(donor->go)) return errno ? errno : EIO;
    donor->pid = rfork(RFPROC | RFFDG);
    if (donor->pid == 0) donor_child(donor, other);
    if (donor->pid < 0) return errno ? errno : EIO;
    close(donor->ready[1]); donor->ready[1] = -1;
    close(donor->go[0]); donor->go[0] = -1;
    int error = ready_byte(donor->ready[0]);
    if (error) return error;
    donor->filedesc = kernel_get_proc_filedesc(donor->pid);
    if (!donor->filedesc ||
        read_ptr(donor->filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR, &rdir) ||
        read_ptr(donor->filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR, &jdir) ||
        kernel_copyout(donor->filedesc + 0x34, &ref_hint,
                       sizeof(ref_hint))) return EFAULT;
    if (rdir != root || jdir != 0 || ref_hint != 1) return EPROTO;
    ps5log_printf(PS5LOG_MARK,
                  "donor_ready build=%s role=%s private=1 root_system=1 jail_null=1 ref_hint=%u",
                  LAPY_PROBE_ID, is_receiver ? "receiver" : "source",
                  ref_hint);
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

/* Under verified single-owner and blocked-child conditions, move one already
 * owned reference from source slot to a null destination. Source is nulled
 * first so a failed destination store cannot create double ownership. */
static int move_to_null(intptr_t source_slot, intptr_t dest_slot,
                        intptr_t root)
{
    intptr_t source = 0, dest = 0;
    if (read_ptr(source_slot, &source) || read_ptr(dest_slot, &dest) ||
        source != root || dest != 0) return EPROTO;
    if (write_ptr(source_slot, 0)) return EFAULT;
    if (write_ptr(dest_slot, root)) {
        /* The destination write may have succeeded despite a readback error.
         * Restore the source only if the destination is definitely null. */
        if (!read_ptr(dest_slot, &dest) && dest == 0)
            write_ptr(source_slot, root);
        return EFAULT;
    }
    return 0;
}

int main(void)
{
    struct donor source = {.pid = -1, .ready = {-1, -1}, .go = {-1, -1}};
    struct donor receiver = {.pid = -1, .ready = {-1, -1}, .go = {-1, -1}};
    intptr_t root = 0, target_fd = 0, target_root = 0, target_jail = 0;
    uint32_t ref_hint = 0, hold = 0, use = 0;
    int error = 0, parent_jail_owned = 0;
    const char *stage = "preflight";

    if (ps5log_init_default("LAPYSWAP", "lapy-null-jail-transfer-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=null-jail-two-donors",
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
        kernel_copyout(target_fd + 0x34, &ref_hint, sizeof(ref_hint))) {
        error = EFAULT;
        goto done;
    }
    if (target_root != root || target_jail || ref_hint != 1) {
        error = EPROTO;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "target_ready build=%s private=1 root_system=1 jail_null=1 ref_hint=%u",
                  LAPY_PROBE_ID, ref_hint);
    stage = "baseline";
    if ((error = sample(root, "baseline", &hold, &use))) goto done;
    stage = "source_donor";
    if ((error = start_donor(&source, 0, root, 0))) goto done;
    stage = "receiver_donor";
    if ((error = start_donor(&receiver, &source, root, 1))) goto done;
    usleep(SETTLE_US);
    stage = "both_held";
    if ((error = sample(root, "both_held", &hold, &use))) goto done;
    stage = "donate";
    if ((error = move_to_null(source.filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                              target_fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                              root))) goto done;
    parent_jail_owned = 1;
    if ((error = sample(root, "donated", &hold, &use))) goto done;
    stage = "source_exit";
    if ((error = exit_donor(&source))) goto done;
    usleep(SETTLE_US);
    if ((error = sample(root, "source_released", &hold, &use))) goto done;
    stage = "return";
    if ((error = move_to_null(target_fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                              receiver.filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                              root))) goto done;
    parent_jail_owned = 0;
    if ((error = sample(root, "returned", &hold, &use))) goto done;
    stage = "receiver_exit";
    if ((error = exit_donor(&receiver))) goto done;
    usleep(SETTLE_US);
    stage = "baseline_restored";
    if ((error = sample(root, "baseline_restored", &hold, &use))) goto done;
    stage = "complete";
done:
    /* A failed transfer can leave a root reference in the parent's jail;
     * its normal process teardown will release that owned reference. */
    cleanup_donor(&source);
    cleanup_donor(&receiver);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d source_reaped=%d receiver_reaped=%d parent_jail_owned=%d",
                  LAPY_PROBE_ID, stage, error, source.reaped,
                  receiver.reaped, parent_jail_owned);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
