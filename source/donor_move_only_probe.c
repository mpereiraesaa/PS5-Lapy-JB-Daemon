/* Move-only reference round trip in disposable filedescs, FW 12.02 only.
 * No title process or vnode counter is written. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include "donor_transaction.h"
#include <errno.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#define CANDIDATE_CDIR 0x08u
#define HINT_REFCOUNT 0x34u
#define HINT_HOLD 0x1bcu
#define HINT_USE 0x1c0u
#define WAIT_MS 5000
#define CHILD_ALARM 15
#define SETTLE_US 20000

struct donor {
    pid_t pid;
    int ready[2], go[2];
    intptr_t filedesc, cdir;
    int reaped;
};

struct counts { uint32_t root_hold, root_use, data_hold, data_use; };

static int read_ptr(void *unused, intptr_t address, intptr_t *value)
{
    (void)unused;
    return kernel_copyout(address, value, sizeof(*value)) ? EFAULT : 0;
}

static int write_ptr(void *unused, intptr_t address, intptr_t value)
{
    (void)unused;
    return kernel_copyin(&value, address, sizeof(value)) ? EFAULT : 0;
}

static int get_root(intptr_t *root)
{
    *root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (*root) return 0;
    intptr_t init_fd = kernel_get_proc_filedesc(1);
    if (!init_fd || read_ptr(0, init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                              root) || !*root) return ENOTSUP;
    return 0;
}

static int sample(intptr_t root, intptr_t data, const char *phase,
                  struct counts *out)
{
    if (kernel_copyout(root + HINT_HOLD, &out->root_hold,
                       sizeof(out->root_hold)) ||
        kernel_copyout(root + HINT_USE, &out->root_use,
                       sizeof(out->root_use)) ||
        (data &&
         (kernel_copyout(data + HINT_HOLD, &out->data_hold,
                         sizeof(out->data_hold)) ||
          kernel_copyout(data + HINT_USE, &out->data_use,
                         sizeof(out->data_use))))) return EFAULT;
    if (!data) out->data_hold = out->data_use = 0;
    ps5log_printf(PS5LOG_MARK,
                  "move_sample build=%s phase=%s root_hold=%u root_use=%u data_known=%d data_hold=%u data_use=%u",
                  LAPY_PROBE_ID, phase, out->root_hold, out->root_use,
                  data != 0, out->data_hold, out->data_use);
    return 0;
}

static int root_matches(intptr_t root, const struct counts *baseline,
                        uint32_t delta)
{
    uint32_t hold = 0, use = 0;
    if (kernel_copyout(root + HINT_HOLD, &hold, sizeof(hold)) ||
        kernel_copyout(root + HINT_USE, &use, sizeof(use))) return EFAULT;
    return hold == baseline->root_hold + delta &&
           use == baseline->root_use + delta ? 0 : EAGAIN;
}

static void child_main(struct donor *self, int chdir_data)
{
    char go = 0;
    close(self->ready[0]); close(self->go[1]);
    alarm(CHILD_ALARM);
    if (chdir_data && chdir("/data")) _exit(2);
    if (write(self->ready[1], "R", 1) != 1) _exit(3);
    if (read(self->go[0], &go, 1) != 1 || go != 'G') _exit(4);
    _exit(0);
}

static int start_donor(struct donor *donor, intptr_t root, int chdir_data)
{
    intptr_t rdir = 0, jdir = 0;
    uint32_t refs = 0;
    if (pipe(donor->ready) || pipe(donor->go))
        return errno ? errno : EIO;
    donor->pid = rfork(RFPROC | RFFDG);
    if (donor->pid == 0) child_main(donor, chdir_data);
    if (donor->pid < 0) return errno ? errno : EIO;
    close(donor->ready[1]); donor->ready[1] = -1;
    close(donor->go[0]); donor->go[0] = -1;
    struct pollfd event = {donor->ready[0], POLLIN, 0};
    char marker = 0;
    int result = poll(&event, 1, WAIT_MS);
    if (result <= 0) return result < 0 ? (errno ? errno : EIO) : ETIMEDOUT;
    if (read(donor->ready[0], &marker, 1) != 1 || marker != 'R')
        return EPROTO;
    donor->filedesc = kernel_get_proc_filedesc(donor->pid);
    if (!donor->filedesc ||
        read_ptr(0, donor->filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                 &rdir) ||
        read_ptr(0, donor->filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                 &jdir) ||
        read_ptr(0, donor->filedesc + CANDIDATE_CDIR,
                 &donor->cdir) ||
        kernel_copyout(donor->filedesc + HINT_REFCOUNT,
                       &refs, sizeof(refs))) return EFAULT;
    if (rdir != root || jdir || refs != 1 || !donor->cdir ||
        (chdir_data ? donor->cdir == root : donor->cdir != root))
        return EPROTO;
    ps5log_printf(PS5LOG_MARK,
                  "donor_ready build=%s role=%s private=1 root_system=1 jail_null=1 cwd_system=%d ref_hint=%u",
                  LAPY_PROBE_ID, chdir_data ? "data" : "root",
                  donor->cdir == root, refs);
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

int main(void)
{
    struct donor data_source = {.pid = -1, .ready = {-1,-1}, .go = {-1,-1}};
    struct donor old_receiver = {.pid = -1, .ready = {-1,-1}, .go = {-1,-1}};
    struct donor root_source = {.pid = -1, .ready = {-1,-1}, .go = {-1,-1}};
    struct donor data_receiver = {.pid = -1, .ready = {-1,-1}, .go = {-1,-1}};
    struct lapy_slot_io io = {read_ptr, write_ptr, 0};
    struct counts baseline = {0}, acquired = {0}, final = {0}, point = {0};
    intptr_t root = 0, data = 0, target_fd = 0;
    intptr_t target_root = 0, target_jail = 0, target_cdir = 0;
    uint32_t target_refs = 0;
    int error = 0;
    enum lapy_replace_result first = LAPY_REPLACE_UNCHANGED;
    enum lapy_replace_result second = LAPY_REPLACE_UNCHANGED;
    const char *stage = "preflight";

    if (ps5log_init_default("LAPYMOVE", "lapy-move-only-donor-probe"))
        return 2;
    signal(SIGPIPE, SIG_IGN);
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=move-only-old-root-round-trip",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    if (kernel_get_fw_version() != 0x12020000 ||
        !KERNEL_OFFSET_FILEDESC_FD_RDIR ||
        !KERNEL_OFFSET_FILEDESC_FD_JDIR) { error = ENOTSUP; goto done; }
    if ((error = get_root(&root))) goto done;
    target_fd = kernel_get_proc_filedesc(getpid());
    if (!target_fd ||
        read_ptr(0, target_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                 &target_root) ||
        read_ptr(0, target_fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                 &target_jail) ||
        read_ptr(0, target_fd + CANDIDATE_CDIR, &target_cdir) ||
        kernel_copyout(target_fd + HINT_REFCOUNT,
                       &target_refs, sizeof(target_refs))) {
        error = EFAULT; goto done;
    }
    if (target_root != root || target_cdir != root || target_jail ||
        target_refs != 1) { error = EPROTO; goto done; }
    stage = "baseline";
    if ((error = sample(root, 0, "baseline", &baseline))) goto done;
    usleep(SETTLE_US);
    if ((error = root_matches(root, &baseline, 0))) goto done;
    stage = "donors";
    if ((error = start_donor(&data_source, root, 1))) goto done;
    data = data_source.cdir;
    if ((error = sample(root, data, "data_acquired", &acquired)) ||
        (error = root_matches(root, &baseline, 1)) ||
        (error = start_donor(&old_receiver, root, 0)) ||
        (error = start_donor(&root_source, root, 0)) ||
        (error = start_donor(&data_receiver, root, 0)) ||
        (error = root_matches(root, &baseline, 7))) goto done;
    stage = "move_to_data";
    first = lapy_replace_owned_ref(
        &io, data_source.filedesc + CANDIDATE_CDIR,
        target_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        old_receiver.filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        data, root);
    if (first != LAPY_REPLACE_COMPLETE) { error = EPROTO; goto done; }
    if ((error = sample(root, data, "data_installed", &point)) ||
        (error = exit_donor(&data_source)) ||
        (error = exit_donor(&old_receiver))) goto done;
    usleep(SETTLE_US);
    if ((error = sample(root, data, "old_root_released", &point)))
        goto done;
    stage = "restore_root";
    second = lapy_replace_owned_ref(
        &io, root_source.filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        target_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        data_receiver.filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        root, data);
    if (second != LAPY_REPLACE_COMPLETE) { error = EPROTO; goto done; }
    if ((error = sample(root, data, "root_restored", &point)) ||
        (error = exit_donor(&root_source)) ||
        (error = exit_donor(&data_receiver))) goto done;
    usleep(SETTLE_US);
    stage = "baseline_restored";
    if ((error = sample(root, data, "baseline_restored", &final))) goto done;
    if (final.root_hold != baseline.root_hold ||
        final.root_use != baseline.root_use ||
        final.data_hold + 1 != acquired.data_hold ||
        final.data_use + 1 != acquired.data_use) {
        error = EPROTO; goto done;
    }
    stage = "complete";
done:
    cleanup_donor(&data_source);
    cleanup_donor(&old_receiver);
    cleanup_donor(&root_source);
    cleanup_donor(&data_receiver);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d first=%d second=%d root_balanced=%d data_released=%d all_reaped=%d",
                  LAPY_PROBE_ID, stage, error, first, second,
                  !error &&
                  final.root_hold == baseline.root_hold &&
                  final.root_use == baseline.root_use,
                  !error &&
                  final.data_hold + 1 == acquired.data_hold &&
                  final.data_use + 1 == acquired.data_use,
                  data_source.reaped && old_receiver.reaped &&
                  root_source.reaped && data_receiver.reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
