/* Verify that PT_ATTACH keeps every thread of a disposable child stopped.
 * This performs no kernel-memory writes and never attaches to a title. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <pthread.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define WAIT_POLLS 100
#define POLL_US 50000
#define OBSERVE_US 100000

static _Atomic uint64_t *ticks;

static void *worker(void *unused)
{
    (void)unused;
    for (;;) {
        atomic_fetch_add_explicit(ticks, 1, memory_order_relaxed);
        usleep(1000);
    }
    return 0;
}

static void child_main(int ready[2], int go[2])
{
    pthread_t thread;
    char command;
    close(ready[0]);
    close(go[1]);
    alarm(15);
    if (pthread_create(&thread, 0, worker, 0)) _exit(2);
    usleep(50000);
    if (write(ready[1], "R", 1) != 1) _exit(3);
    if (read(go[0], &command, 1) != 1 || command != 'G') _exit(4);
    _exit(0);
}

static int await_stop(pid_t child, int *status)
{
    for (unsigned i = 0; i < WAIT_POLLS; ++i) {
        pid_t result = waitpid(child, status, WNOHANG | WUNTRACED);
        if (result == child)
            return WIFSTOPPED(*status) ? 0 : EPROTO;
        if (result < 0) return errno ? errno : ECHILD;
        usleep(POLL_US);
    }
    return ETIMEDOUT;
}

static int await_exit(pid_t child, int *status)
{
    for (unsigned i = 0; i < WAIT_POLLS; ++i) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child)
            return WIFEXITED(*status) && WEXITSTATUS(*status) == 0 ? 0 : EPROTO;
        if (result < 0) return errno ? errno : ECHILD;
        usleep(POLL_US);
    }
    return ETIMEDOUT;
}

int main(void)
{
    int ready[2] = {-1, -1}, go[2] = {-1, -1};
    int error = 0, status = 0, attached = 0, reaped = 0;
    int threads = -1, listed = -1, stop_signal = -1;
    pid_t child = -1, tids[8] = {0};
    struct reg registers;
    uint64_t before_stop = 0, stopped_a = 0, stopped_b = 0, resumed = 0;
    const char *stage = "setup";

    if (ps5log_init_default("LAPYTRACE", "lapy-ptrace-quiescence-probe"))
        return 2;
    signal(SIGPIPE, SIG_IGN);
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=disposable-multithread-ptrace",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    ticks = mmap(0, sizeof(*ticks), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANON, -1, 0);
    if (ticks == MAP_FAILED) { error = errno ? errno : EIO; goto done; }
    atomic_init(ticks, 0);
    if (pipe(ready) || pipe(go)) { error = errno ? errno : EIO; goto done; }
    stage = "create_child";
    child = rfork(RFPROC | RFFDG);
    if (child == 0) child_main(ready, go);
    if (child < 0) { error = errno ? errno : EIO; goto done; }
    close(ready[1]); ready[1] = -1;
    close(go[0]); go[0] = -1;
    char marker = 0;
    stage = "child_ready";
    if (read(ready[0], &marker, 1) != 1 || marker != 'R') {
        error = EPROTO; goto done;
    }
    before_stop = atomic_load_explicit(ticks, memory_order_relaxed);
    if (before_stop == 0) { error = EPROTO; goto done; }
    stage = "attach";
    if (ptrace(PT_ATTACH, child, 0, 0) < 0) {
        error = errno ? errno : EIO; goto done;
    }
    attached = 1;
    stage = "wait_stop";
    if ((error = await_stop(child, &status))) goto done;
    stop_signal = WSTOPSIG(status);
    stage = "thread_snapshot";
    threads = ptrace(PT_GETNUMLWPS, child, 0, 0);
    if (threads < 2 || threads > (int)(sizeof(tids) / sizeof(tids[0]))) {
        error = threads < 0 ? (errno ? errno : EIO) : EPROTO;
        goto done;
    }
    listed = ptrace(PT_GETLWPLIST, child, (caddr_t)tids, threads);
    if (listed != threads || tids[0] <= 0 || tids[1] <= 0) {
        error = listed < 0 ? (errno ? errno : EIO) : EPROTO;
        goto done;
    }
    /* FreeBSD's ptrace register read requires a fully stopped tracee. */
    if (ptrace(PT_GETREGS, child, (caddr_t)&registers, 0) < 0) {
        error = errno ? errno : EIO; goto done;
    }
    stopped_a = atomic_load_explicit(ticks, memory_order_relaxed);
    usleep(OBSERVE_US);
    stopped_b = atomic_load_explicit(ticks, memory_order_relaxed);
    if (stopped_a != stopped_b) { error = EBUSY; goto done; }
    stage = "detach";
    if (ptrace(PT_DETACH, child, 0, 0) < 0) {
        error = errno ? errno : EIO; goto done;
    }
    attached = 0;
    usleep(OBSERVE_US);
    resumed = atomic_load_explicit(ticks, memory_order_relaxed);
    if (resumed <= stopped_b) { error = EPROTO; goto done; }
    stage = "child_exit";
    if (write(go[1], "G", 1) != 1) { error = EPIPE; goto done; }
    error = await_exit(child, &status);
    if (!error) { reaped = 1; stage = "complete"; }

done:
    if (attached && ptrace(PT_DETACH, child, 0, 0) == 0) attached = 0;
    if (child > 0 && !reaped) {
        kill(child, SIGKILL);
        if (!attached) waitpid(child, &status, 0);
    }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (go[0] >= 0) close(go[0]);
    if (go[1] >= 0) close(go[1]);
    if (ticks && ticks != MAP_FAILED) munmap((void *)ticks, sizeof(*ticks));
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d threads=%d listed=%d stop_signal=%d counter_before=%llu counter_stopped_a=%llu counter_stopped_b=%llu counter_resumed=%llu detached=%d reaped=%d",
                  LAPY_PROBE_ID, stage, error, threads, listed, stop_signal,
                  (unsigned long long)before_stop,
                  (unsigned long long)stopped_a,
                  (unsigned long long)stopped_b,
                  (unsigned long long)resumed, !attached, reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
