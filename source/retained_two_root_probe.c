/* FW 12.02 disposable two-root ownership transfer under a debugger stop.
 * This does not modify credentials or a title process. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include "donor_transaction.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROC_THREADS_HEAD 0x10u
#define PROC_PID_OFFSET 0xbcu
#define PROC_SUSPCOUNT 0x3a0u
#define THREAD_PROC 0x08u
#define THREAD_NEXT 0x10u
#define FD_REFCNT 0x34u
#define ROOT_HOLD 0x1bcu
#define ROOT_USE 0x1c0u
#define MAX_THREADS 16u

struct child {
    pid_t pid;
    int ready[2], release[2];
    intptr_t proc, fd;
    int reaped, stop_sent;
};

struct snapshot {
    intptr_t proc, fd, threads[MAX_THREADS];
    unsigned count, suspended;
    uint32_t fd_refs;
    intptr_t root, jail;
};

struct counts { uint32_t hold, use; };

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

static int sample_root(intptr_t root, const char *phase,
                       struct counts *out)
{
    if (kernel_copyout(root + ROOT_HOLD, &out->hold,
                       sizeof(out->hold)) ||
        kernel_copyout(root + ROOT_USE, &out->use,
                       sizeof(out->use))) return EFAULT;
    ps5log_printf(PS5LOG_MARK,
                  "root_sample build=%s phase=%s hold=%u use=%u",
                  LAPY_PROBE_ID, phase, out->hold, out->use);
    return 0;
}

static int expect_delta(const struct counts *baseline,
                        const struct counts *observed, uint32_t delta)
{
    return observed->hold == baseline->hold + delta &&
           observed->use == baseline->use + delta ? 0 : EAGAIN;
}

static void *worker(void *unused)
{
    (void)unused;
    for (;;) usleep(1000);
    return 0;
}

static void child_main(struct child *self, int with_worker)
{
    pthread_t thread;
    char command = 0;
    close(self->ready[0]); close(self->release[1]);
    alarm(30);
    if (with_worker && pthread_create(&thread, 0, worker, 0)) _exit(2);
    if (write(self->ready[1], "R", 1) != 1) _exit(2);
    if (read(self->release[0], &command, 1) != 1 || command != 'G') _exit(3);
    _exit(0);
}

static int start_child(struct child *self, int with_worker)
{
    char marker = 0;
    if (pipe(self->ready) || pipe(self->release)) return errno ? errno : EIO;
    self->pid = rfork(RFPROC | RFFDG);
    if (self->pid == 0) child_main(self, with_worker);
    if (self->pid < 0) return errno ? errno : EIO;
    close(self->ready[1]); self->ready[1] = -1;
    close(self->release[0]); self->release[0] = -1;
    struct pollfd event = {self->ready[0], POLLIN, 0};
    if (poll(&event, 1, 5000) != 1 ||
        read(self->ready[0], &marker, 1) != 1 || marker != 'R')
        return ETIMEDOUT;
    return 0;
}

static int snapshot(pid_t pid, struct snapshot *out)
{
    pid_t observed = 0;
    intptr_t current = 0, owner = 0, next = 0;
    memset(out, 0, sizeof(*out));
    out->proc = kernel_get_proc(pid);
    if (!out->proc || kernel_copyout(out->proc + PROC_PID_OFFSET,
                                      &observed, sizeof(observed)) ||
        observed != pid) return ESRCH;
    out->fd = kernel_get_proc_filedesc(pid);
    if (!out->fd ||
        kernel_copyout(out->fd + FD_REFCNT, &out->fd_refs,
                       sizeof(out->fd_refs)) ||
        kernel_copyout(out->proc + PROC_SUSPCOUNT, &out->suspended,
                       sizeof(out->suspended)) ||
        read_ptr(0, out->fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                 &out->root) ||
        read_ptr(0, out->fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                 &out->jail) ||
        read_ptr(0, out->proc + PROC_THREADS_HEAD, &current)) return EFAULT;
    while (current) {
        if (out->count >= MAX_THREADS) return EOVERFLOW;
        for (unsigned i = 0; i < out->count; ++i)
            if (out->threads[i] == current) return ELOOP;
        out->threads[out->count++] = current;
        if (read_ptr(0, current + THREAD_PROC, &owner) ||
            read_ptr(0, current + THREAD_NEXT, &next) ||
            owner != out->proc) return EFAULT;
        current = next;
    }
    return out->count ? 0 : EPROTO;
}

static int same_stop(const struct snapshot *first,
                     const struct snapshot *second)
{
    return first->proc == second->proc && first->fd == second->fd &&
           first->count == second->count && first->fd_refs == 1 &&
           second->fd_refs == 1 && first->count == first->suspended &&
           second->count == second->suspended &&
           !memcmp(first->threads, second->threads,
                   first->count * sizeof(first->threads[0]));
}

static int await_stop(struct child *target, intptr_t root,
                      struct snapshot *stopped)
{
    struct snapshot first, second;
    for (unsigned i = 0; i < 120; ++i) {
        int err = snapshot(target->pid, &first);
        if (err) return err;
        if (first.proc != target->proc || first.fd != target->fd ||
            first.fd_refs != 1 || first.root != root || first.jail)
            return EPROTO;
        if (first.count == 2 && first.suspended == 2) {
            usleep(50000);
            err = snapshot(target->pid, &second);
            if (err) return err;
            if (same_stop(&first, &second) && second.root == root &&
                !second.jail) {
                *stopped = second;
                return 0;
            }
        }
        usleep(100000);
    }
    return ETIMEDOUT;
}

static int release_child(struct child *self)
{
    int status = 0;
    if (self->stop_sent) {
        if (kill(self->pid, SIGCONT)) return errno ? errno : EIO;
        self->stop_sent = 0;
    }
    if (write(self->release[1], "G", 1) != 1) return EPIPE;
    for (unsigned i = 0; i < 150; ++i) {
        pid_t result = waitpid(self->pid, &status, WNOHANG);
        if (result == self->pid) {
            self->reaped = 1;
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : EPROTO;
        }
        if (result < 0) return errno ? errno : ECHILD;
        usleep(100000);
    }
    return ETIMEDOUT;
}

static int stop_donor(struct child *donor, intptr_t root)
{
    struct snapshot first, second;
    if (kill(donor->pid, SIGSTOP)) return errno ? errno : EIO;
    donor->stop_sent = 1;
    for (unsigned i = 0; i < 100; ++i) {
        int err = snapshot(donor->pid, &first);
        if (err) return err;
        if (first.proc != donor->proc || first.fd != donor->fd ||
            first.fd_refs != 1 || first.root != root || first.jail ||
            first.count != 1) return EPROTO;
        if (first.suspended == 1) {
            usleep(50000);
            err = snapshot(donor->pid, &second);
            if (err) return err;
            if (same_stop(&first, &second) && second.root == root &&
                !second.jail) return 0;
        }
        usleep(50000);
    }
    return ETIMEDOUT;
}

static void cleanup_child(struct child *self)
{
    if (self->pid > 0 && !self->reaped) {
        kill(self->pid, SIGCONT);
        kill(self->pid, SIGKILL);
        waitpid(self->pid, 0, 0);
    }
    if (self->ready[0] >= 0) close(self->ready[0]);
    if (self->ready[1] >= 0) close(self->ready[1]);
    if (self->release[0] >= 0) close(self->release[0]);
    if (self->release[1] >= 0) close(self->release[1]);
}

int main(void)
{
    struct child target = {.pid = -1, .ready = {-1,-1},
                           .release = {-1,-1}};
    struct child first = {.pid = -1, .ready = {-1,-1},
                          .release = {-1,-1}};
    struct child second = {.pid = -1, .ready = {-1,-1},
                           .release = {-1,-1}};
    struct snapshot initial, stopped, first_state, second_state, confirmed;
    struct counts baseline = {0}, observed = {0};
    struct lapy_slot_io io = {read_ptr, write_ptr, 0};
    intptr_t root = 0;
    int error = 0, moved = 0, intermediate_noise = 0;
    const char *stage = "preflight";
    if (ps5log_init_default("LAPY2ROOT", "lapy-retained-two-root"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=retained-two-root",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    if (kernel_get_fw_version() != 0x12020000 ||
        KERNEL_OFFSET_PROC_P_PID != PROC_PID_OFFSET ||
        !KERNEL_OFFSET_FILEDESC_FD_RDIR ||
        !KERNEL_OFFSET_FILEDESC_FD_JDIR) {
        error = ENOTSUP; goto done;
    }
    root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (!root) {
        intptr_t init_fd = kernel_get_proc_filedesc(1);
        if (!init_fd ||
            read_ptr(0, init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                     &root)) root = 0;
    }
    if (!root) { error = ENOTSUP; goto done; }
    if ((error = sample_root(root, "baseline", &baseline))) goto done;
    stage = "target_start";
    if ((error = start_child(&target, 1)) ||
        (error = snapshot(target.pid, &initial))) goto done;
    target.proc = initial.proc; target.fd = initial.fd;
    if (initial.fd_refs != 1 || initial.root != root || initial.jail ||
        initial.count != 2 || initial.suspended) {
        error = EPROTO; goto done;
    }
    if ((error = sample_root(root, "target_ready", &observed)) ||
        (error = expect_delta(&baseline, &observed, 2))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "target_ready build=%s pid=%d threads=%u private=%d root_system=%d jail_null=%d hold_seconds=12",
                  LAPY_PROBE_ID, target.pid, initial.count,
                  initial.fd_refs == 1, initial.root == root, !initial.jail);
    stage = "target_stop";
    if ((error = await_stop(&target, root, &stopped))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "target_stopped build=%s pid=%d threads=%u suspended=%u",
                  LAPY_PROBE_ID, target.pid, stopped.count,
                  stopped.suspended);
    stage = "first_donor_start";
    if ((error = start_child(&first, 0)) ||
        (error = snapshot(first.pid, &first_state))) goto done;
    first.proc = first_state.proc; first.fd = first_state.fd;
    if (first_state.fd_refs != 1 || first_state.root != root ||
        first_state.jail || first_state.suspended || first_state.count != 1 ||
        (error = snapshot(target.pid, &confirmed)) ||
        !same_stop(&stopped, &confirmed) || confirmed.jail) {
        error = EPROTO; goto done;
    }
    if ((error = stop_donor(&first, root))) goto done;
    if ((error = sample_root(root, "first_ready", &observed)) ||
        (error = expect_delta(&baseline, &observed, 4))) goto done;
    stage = "second_donor_start";
    if ((error = start_child(&second, 0)) ||
        (error = snapshot(second.pid, &second_state))) goto done;
    second.proc = second_state.proc; second.fd = second_state.fd;
    if (second_state.fd_refs != 1 || second_state.root != root ||
        second_state.jail || second_state.suspended ||
        second_state.count != 1 ||
        (error = snapshot(target.pid, &confirmed)) ||
        !same_stop(&stopped, &confirmed) || confirmed.jail) {
        error = EPROTO; goto done;
    }
    if ((error = stop_donor(&second, root))) goto done;
    if ((error = sample_root(root, "donors_ready", &observed)) ||
        (error = expect_delta(&baseline, &observed, 6))) goto done;
    stage = "transfer";
    enum lapy_replace_result result = lapy_replace_two_roots(
        &io, first.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        second.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        target.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        target.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        first.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        second.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        root, root, 0);
    if (result == LAPY_REPLACE_HELD) {
        ps5log_printf(PS5LOG_ERR,
                      "probe_held build=%s stage=transfer retain_owners=1",
                      LAPY_PROBE_ID);
        for (;;) sleep(1);
    }
    if (result != LAPY_REPLACE_COMPLETE) { error = EPROTO; goto done; }
    moved = 1;
    if ((error = snapshot(target.pid, &confirmed)) ||
        !same_stop(&stopped, &confirmed) ||
        confirmed.root != root || confirmed.jail != root ||
        (error = snapshot(first.pid, &first_state)) ||
        first_state.root || first_state.jail != root ||
        first_state.suspended != 1 ||
        (error = snapshot(second.pid, &second_state)) ||
        second_state.root || second_state.jail ||
        second_state.suspended != 1) {
        error = EPROTO; goto done;
    }
    if ((error = sample_root(root, "transfer_committed", &observed)) ||
        (error = expect_delta(&baseline, &observed, 6))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "transfer_committed build=%s target_stopped=1 target_root_system=1 target_jail_system=1 first_old_root_received=1 donor_roots_null=1",
                  LAPY_PROBE_ID);
    stage = "first_donor_exit";
    if ((error = release_child(&first))) goto done;
    if ((error = sample_root(root, "first_reaped", &observed))) goto done;
    if (expect_delta(&baseline, &observed, 4)) {
        intermediate_noise = 1;
        ps5log_printf(PS5LOG_MARK,
                      "root_interference build=%s phase=first_reaped",
                      LAPY_PROBE_ID);
    }
    stage = "second_donor_exit";
    if ((error = release_child(&second))) goto done;
    if ((error = sample_root(root, "second_reaped", &observed))) goto done;
    if (expect_delta(&baseline, &observed, 3)) {
        intermediate_noise = 1;
        ps5log_printf(PS5LOG_MARK,
                      "root_interference build=%s phase=second_reaped",
                      LAPY_PROBE_ID);
    }
    stage = "target_exit";
    if ((error = release_child(&target))) goto done;
    for (unsigned i = 0; i < 20; ++i) {
        if ((error = sample_root(root, "target_reaped", &observed)))
            goto done;
        if (!expect_delta(&baseline, &observed, 0)) break;
        usleep(50000);
    }
    if ((error = expect_delta(&baseline, &observed, 0))) goto done;
    stage = "complete";
done:
    cleanup_child(&second);
    cleanup_child(&first);
    cleanup_child(&target);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d moved=%d first_reaped=%d second_reaped=%d target_reaped=%d intermediate_noise=%d",
                  LAPY_PROBE_ID, stage, error, moved, first.reaped,
                  second.reaped, target.reaped, intermediate_noise);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
