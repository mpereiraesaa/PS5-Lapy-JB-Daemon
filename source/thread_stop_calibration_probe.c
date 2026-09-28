/* Disposable 1->2->3 thread and SIGSTOP/SIGCONT proc-field calibration.
 * Reads kernel memory but never writes it or signals a title process. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROC_BYTES 0x700u
#define WAIT_MS 5000
#define OBSERVE_US 100000
#define PROC_THREADS_HEAD 0x10u
#define THREAD_PROC 0x08u
#define THREAD_NEXT 0x10u

static _Atomic uint64_t *ticks;
static _Atomic int *finish;

static void *worker(void *unused)
{
    (void)unused;
    while (!atomic_load_explicit(finish, memory_order_relaxed)) {
        atomic_fetch_add_explicit(ticks, 1, memory_order_relaxed);
        usleep(1000);
    }
    return 0;
}

static int receive(int fd, char expected)
{
    struct pollfd event = {fd, POLLIN, 0};
    char value = 0;
    int result = poll(&event, 1, WAIT_MS);
    if (result <= 0) return result ? (errno ? errno : EIO) : ETIMEDOUT;
    return read(fd, &value, 1) == 1 && value == expected ? 0 : EPROTO;
}

static void child_main(int command[2], int report[2])
{
    pthread_t first, second;
    char action = 0;
    close(command[1]); close(report[0]);
    alarm(15);
    if (write(report[1], "R", 1) != 1) _exit(2);
    if (read(command[0], &action, 1) != 1 || action != 'A' ||
        pthread_create(&first, 0, worker, 0) ||
        write(report[1], "A", 1) != 1) _exit(3);
    if (read(command[0], &action, 1) != 1 || action != 'B' ||
        pthread_create(&second, 0, worker, 0) ||
        write(report[1], "B", 1) != 1) _exit(4);
    if (read(command[0], &action, 1) != 1 || action != 'G') _exit(5);
    atomic_store_explicit(finish, 1, memory_order_relaxed);
    if (pthread_join(first, 0) || pthread_join(second, 0)) _exit(6);
    _exit(0);
}

static int snapshot(pid_t child, intptr_t *proc, uint8_t bytes[PROC_BYTES])
{
    pid_t observed = 0;
    intptr_t address = kernel_get_proc(child);
    if (!address || !KERNEL_OFFSET_PROC_P_PID ||
        kernel_copyout(address + KERNEL_OFFSET_PROC_P_PID,
                       &observed, sizeof(observed)) || observed != child ||
        kernel_copyout(address, bytes, PROC_BYTES)) return EFAULT;
    *proc = address;
    return 0;
}

static uint32_t word(const uint8_t bytes[PROC_BYTES], unsigned at)
{
    uint32_t value = 0;
    memcpy(&value, bytes + at, sizeof(value));
    return value;
}

static int thread_list_count(intptr_t proc, const uint8_t bytes[PROC_BYTES],
                             unsigned *count)
{
    intptr_t current = 0, owner = 0, next = 0;
    intptr_t seen[16];
    memcpy(&current, bytes + PROC_THREADS_HEAD, sizeof(current));
    *count = 0;
    while (current) {
        if (*count >= 16) return EOVERFLOW;
        for (unsigned i = 0; i < *count; ++i)
            if (seen[i] == current) return ELOOP;
        seen[(*count)++] = current;
        if (kernel_copyout(current + THREAD_PROC, &owner, sizeof(owner)) ||
            kernel_copyout(current + THREAD_NEXT, &next, sizeof(next)) ||
            owner != proc) return EFAULT;
        current = next;
    }
    return 0;
}

static int stopped_child(pid_t child, int *status)
{
    for (unsigned i = 0; i < WAIT_MS / 50; ++i) {
        pid_t result = waitpid(child, status, WNOHANG | WUNTRACED);
        if (result == child)
            return WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGSTOP ? 0 : EPROTO;
        if (result < 0) return errno ? errno : ECHILD;
        usleep(50000);
    }
    return ETIMEDOUT;
}

int main(void)
{
    uint8_t one[PROC_BYTES], two[PROC_BYTES], three[PROC_BYTES];
    uint8_t stopped[PROC_BYTES], resumed[PROC_BYTES];
    int command[2] = {-1, -1}, report[2] = {-1, -1};
    intptr_t proc1 = 0, proc2 = 0, proc3 = 0, procs = 0, procr = 0;
    pid_t child = -1;
    int error = 0, status = 0, reaped = 0, sent_stop = 0, sent_cont = 0;
    unsigned stop_candidates = 0, stop_offset = 0;
    unsigned list_one = 0, list_two = 0, list_three = 0;
    unsigned list_stopped = 0, list_resumed = 0;
    uint64_t tick_a = 0, tick_b = 0, tick_after = 0;
    const char *stage = "setup";

    if (ps5log_init_default("LAPYTC", "lapy-thread-stop-calibration")) return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=disposable-1-2-3-thread-stop",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    ticks = mmap(0, sizeof(*ticks), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANON, -1, 0);
    if (ticks == MAP_FAILED) { ticks = 0; error = errno; goto done; }
    finish = mmap(0, sizeof(*finish), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANON, -1, 0);
    if (finish == MAP_FAILED) { finish = 0; error = errno; goto done; }
    atomic_init(ticks, 0);
    atomic_init(finish, 0);
    if (pipe(command) || pipe(report)) { error = errno; goto done; }
    stage = "create_child";
    child = rfork(RFPROC | RFFDG);
    if (child == 0) child_main(command, report);
    if (child < 0) { error = errno; goto done; }
    close(command[0]); command[0] = -1;
    close(report[1]); report[1] = -1;
    stage = "one_thread";
    if ((error = receive(report[0], 'R')) ||
        (error = snapshot(child, &proc1, one)) ||
        (error = thread_list_count(proc1, one, &list_one))) goto done;
    stage = "two_threads";
    if (write(command[1], "A", 1) != 1 ||
        (error = receive(report[0], 'A')) ||
        (error = snapshot(child, &proc2, two)) ||
        (error = thread_list_count(proc2, two, &list_two))) {
        if (!error) error = EPIPE;
        goto done;
    }
    stage = "three_threads";
    if (write(command[1], "B", 1) != 1 ||
        (error = receive(report[0], 'B')) ||
        (error = snapshot(child, &proc3, three)) ||
        (error = thread_list_count(proc3, three, &list_three))) {
        if (!error) error = EPIPE;
        goto done;
    }
    if (proc1 != proc2 || proc2 != proc3) { error = ESTALE; goto done; }
    stage = "stop";
    if (kill(child, SIGSTOP)) { error = errno; goto done; }
    sent_stop = 1;
    if ((error = stopped_child(child, &status)) ||
        (error = snapshot(child, &procs, stopped)) ||
        (error = thread_list_count(procs, stopped, &list_stopped))) goto done;
    tick_a = atomic_load_explicit(ticks, memory_order_relaxed);
    usleep(OBSERVE_US);
    tick_b = atomic_load_explicit(ticks, memory_order_relaxed);
    if (tick_a != tick_b) { error = EBUSY; goto done; }
    stage = "resume";
    if (kill(child, SIGCONT)) { error = errno; goto done; }
    sent_cont = 1;
    usleep(OBSERVE_US);
    tick_after = atomic_load_explicit(ticks, memory_order_relaxed);
    if (tick_after <= tick_b ||
        (error = snapshot(child, &procr, resumed)) || procr != proc1 ||
        procs != proc1) {
        if (!error) error = EPROTO;
        goto done;
    }
    stage = "thread_list";
    if ((error = thread_list_count(procr, resumed, &list_resumed))) goto done;
    for (unsigned at = 0; at + 4 <= PROC_BYTES; at += 4) {
        if (word(one, at) == 0 && word(two, at) == 0 &&
            word(three, at) == 0 && word(stopped, at) == 3 &&
            word(resumed, at) == 0) {
            ++stop_candidates;
            stop_offset = at;
        }
    }
    if (list_one != 1 || list_two != 2 || list_three != 3 ||
        list_stopped != 3 || list_resumed != 3 ||
        stop_candidates != 1) { error = EPROTO; goto done; }
    stage = "child_exit";
    if (write(command[1], "G", 1) != 1 ||
        waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status)) {
        error = ECHILD; goto done;
    }
    reaped = 1;
    stage = "complete";
done:
    if (child > 0 && !reaped) {
        if (sent_stop && !sent_cont) kill(child, SIGCONT);
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    if (command[0] >= 0) close(command[0]);
    if (command[1] >= 0) close(command[1]);
    if (report[0] >= 0) close(report[0]);
    if (report[1] >= 0) close(report[1]);
    if (ticks) munmap((void *)ticks, sizeof(*ticks));
    if (finish) munmap((void *)finish, sizeof(*finish));
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d list_counts=%u,%u,%u,%u,%u stop_candidates=%u stop_offset=0x%x ticks_stable=%d ticks_resumed=%d proc_stable=%d reaped=%d",
                  LAPY_PROBE_ID, stage, error, list_one, list_two,
                  list_three, list_stopped, list_resumed, stop_candidates,
                  stop_offset,
                  tick_a == tick_b && tick_a != 0, tick_after > tick_b,
                  proc1 && proc1 == proc2 && proc2 == proc3 &&
                  proc3 == procs && procs == procr, reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
