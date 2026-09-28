/* Disposable multithread SIGSTOP gate. No ptrace, target title or writes to
 * kernel memory. The proc snapshots are diagnostic, not a licensed offset. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <pthread.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROC_BYTES 0x700u
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
    close(ready[0]); close(go[1]);
    alarm(15);
    if (pthread_create(&thread, 0, worker, 0)) _exit(2);
    usleep(50000);
    if (write(ready[1], "R", 1) != 1) _exit(3);
    if (read(go[0], &command, 1) != 1 || command != 'G') _exit(4);
    _exit(0);
}

static int wait_event(pid_t child, int options, int *status)
{
    for (unsigned i = 0; i < WAIT_POLLS; ++i) {
        pid_t result = waitpid(child, status, WNOHANG | options);
        if (result == child) return 0;
        if (result < 0) return errno ? errno : ECHILD;
        usleep(POLL_US);
    }
    return ETIMEDOUT;
}

static int snapshot(pid_t child, intptr_t *proc, uint8_t bytes[PROC_BYTES])
{
    pid_t observed_pid = 0;
    intptr_t address = kernel_get_proc(child);
    if (!address || !KERNEL_OFFSET_PROC_P_PID ||
        kernel_copyout(address + KERNEL_OFFSET_PROC_P_PID,
                       &observed_pid, sizeof(observed_pid)) ||
        observed_pid != child ||
        kernel_copyout(address, bytes, PROC_BYTES)) return EFAULT;
    *proc = address;
    return 0;
}

static int thread_states(pid_t child, unsigned *total, unsigned *stopped)
{
    struct kinfo_proc info[8];
    size_t length = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC,
                  KERN_PROC_PID | KERN_PROC_INC_THREAD, child};
    if (sysctl(mib, 4, info, &length, 0, 0) < 0)
        return errno ? errno : EIO;
    if (!length || length % sizeof(info[0])) return EPROTO;
    *total = (unsigned)(length / sizeof(info[0]));
    *stopped = 0;
    for (unsigned i = 0; i < *total; ++i) {
        if (info[i].ki_pid != child) return EPROTO;
        if (info[i].ki_stat == SSTOP) ++*stopped;
    }
    return 0;
}

static uint32_t word(const uint8_t bytes[PROC_BYTES], unsigned offset)
{
    uint32_t result;
    memcpy(&result, bytes + offset, sizeof(result));
    return result;
}

int main(void)
{
    uint8_t baseline[PROC_BYTES], stopped[PROC_BYTES], resumed[PROC_BYTES];
    int ready[2] = {-1, -1}, go[2] = {-1, -1};
    intptr_t proc_before = 0, proc_stopped = 0, proc_after = 0;
    uint64_t tick_before = 0, tick_a = 0, tick_b = 0, tick_after = 0;
    unsigned threads = 2, reported_threads = 0, stopped_threads = 0;
    unsigned candidates = 0;
    unsigned candidate[4] = {0, 0, 0, 0};
    pid_t child = -1;
    int error = 0, status = 0, reaped = 0, sent_stop = 0, sent_cont = 0;
    int kinfo_error = 0;
    const char *stage = "setup";

    if (ps5log_init_default("LAPYSTOP", "lapy-signal-quiescence-probe"))
        return 2;
    signal(SIGPIPE, SIG_IGN);
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=disposable-multithread-sigstop proc_bytes=%u",
                  LAPY_PROBE_ID, kernel_get_fw_version(), PROC_BYTES);
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
    stage = "baseline";
    if ((error = snapshot(child, &proc_before, baseline))) goto done;
    tick_before = atomic_load_explicit(ticks, memory_order_relaxed);
    if (!tick_before) { error = EPROTO; goto done; }
    stage = "send_stop";
    if (kill(child, SIGSTOP)) { error = errno ? errno : EIO; goto done; }
    sent_stop = 1;
    stage = "wait_stop";
    if ((error = wait_event(child, WUNTRACED, &status))) goto done;
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        error = EPROTO; goto done;
    }
    stage = "stopped_snapshot";
    if ((error = snapshot(child, &proc_stopped, stopped))) goto done;
    kinfo_error = thread_states(child, &reported_threads, &stopped_threads);
    if (kinfo_error && kinfo_error != ENOENT && kinfo_error != ENOTSUP) {
        error = kinfo_error; goto done;
    }
    if ((!kinfo_error &&
         (reported_threads != threads || stopped_threads != threads)) ||
        proc_before != proc_stopped) { error = EPROTO; goto done; }
    tick_a = atomic_load_explicit(ticks, memory_order_relaxed);
    usleep(OBSERVE_US);
    tick_b = atomic_load_explicit(ticks, memory_order_relaxed);
    if (tick_a != tick_b) { error = EBUSY; goto done; }
    stage = "send_continue";
    if (kill(child, SIGCONT)) { error = errno ? errno : EIO; goto done; }
    sent_cont = 1;
    usleep(OBSERVE_US);
    tick_after = atomic_load_explicit(ticks, memory_order_relaxed);
    if (tick_after <= tick_b) { error = EPROTO; goto done; }
    stage = "resumed_snapshot";
    if ((error = snapshot(child, &proc_after, resumed))) goto done;
    if (proc_after != proc_before) { error = EPROTO; goto done; }
    for (unsigned offset = 0; offset + sizeof(uint32_t) <= PROC_BYTES;
         offset += sizeof(uint32_t)) {
        if (word(baseline, offset) == 0 &&
            word(stopped, offset) == threads &&
            word(resumed, offset) == 0) {
            if (candidates < 4) candidate[candidates] = offset;
            ++candidates;
        }
    }
    stage = "child_exit";
    if (write(go[1], "G", 1) != 1) { error = EPIPE; goto done; }
    if ((error = wait_event(child, 0, &status))) goto done;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        error = EPROTO; goto done;
    }
    reaped = 1;
    stage = "complete";
done:
    if (child > 0 && !reaped) {
        if (sent_stop && !sent_cont) kill(child, SIGCONT);
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (go[0] >= 0) close(go[0]);
    if (go[1] >= 0) close(go[1]);
    if (ticks && ticks != MAP_FAILED) munmap((void *)ticks, sizeof(*ticks));
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d expected_threads=%u reported_threads=%u stopped_threads=%u kinfo_error=%d tick_before=%llu tick_stopped_a=%llu tick_stopped_b=%llu tick_resumed=%llu proc_stable=%d candidates=%u offset0=0x%x offset1=0x%x offset2=0x%x offset3=0x%x stop_sent=%d cont_sent=%d reaped=%d",
                  LAPY_PROBE_ID, stage, error, threads, reported_threads,
                  stopped_threads, kinfo_error,
                  (unsigned long long)tick_before,
                  (unsigned long long)tick_a,
                  (unsigned long long)tick_b,
                  (unsigned long long)tick_after,
                  proc_before && proc_before == proc_stopped &&
                  proc_stopped == proc_after, candidates,
                  candidate[0], candidate[1], candidate[2], candidate[3],
                  sent_stop, sent_cont, reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
