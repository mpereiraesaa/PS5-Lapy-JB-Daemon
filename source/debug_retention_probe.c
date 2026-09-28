/* Disposable child for testing ps5debug-ng's retained debug stop path.
 * No target title, kernel write, credential change or root edit. */
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
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

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

static void child_main(int ready[2], int release[2])
{
    pthread_t thread;
    char command = 0;
    close(ready[0]); close(release[1]);
    alarm(30);
    if (pthread_create(&thread, 0, worker, 0) ||
        write(ready[1], "R", 1) != 1) _exit(2);
    if (read(release[0], &command, 1) != 1 || command != 'G') _exit(3);
    _exit(0);
}

int main(void)
{
    int ready[2] = {-1,-1}, release[2] = {-1,-1};
    pid_t child = -1;
    int error = 0, status = 0, reaped = 0;
    uint64_t before = 0, after = 0, last = 0;
    unsigned unchanged = 0;
    int plateau = 0, resumed_after_plateau = 0;
    const char *stage = "setup";

    if (ps5log_init_default("LAPYRET", "lapy-debug-retention-probe")) return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=disposable-debug-retention",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    ticks = mmap(0, sizeof(*ticks), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANON, -1, 0);
    if (ticks == MAP_FAILED) { ticks = 0; error = errno; goto done; }
    atomic_init(ticks, 0);
    if (pipe(ready) || pipe(release)) { error = errno; goto done; }
    stage = "child_create";
    child = rfork(RFPROC | RFFDG);
    if (child == 0) child_main(ready, release);
    if (child < 0) { error = errno; goto done; }
    close(ready[1]); ready[1] = -1;
    close(release[0]); release[0] = -1;
    struct pollfd event = {ready[0], POLLIN, 0};
    char marker = 0;
    stage = "child_ready";
    if (poll(&event, 1, 5000) != 1 ||
        read(ready[0], &marker, 1) != 1 || marker != 'R') {
        error = EPROTO; goto done;
    }
    for (unsigned i = 0; i < 20; ++i) {
        before = atomic_load_explicit(ticks, memory_order_relaxed);
        if (before >= 20) break;
        usleep(50000);
    }
    if (before < 20) { error = EPROTO; goto done; }
    ps5log_printf(PS5LOG_MARK,
                  "child_ready build=%s pid=%d worker_started=%d hold_seconds=15",
                  LAPY_PROBE_ID, (int)child, before > 0);
    stage = "host_window";
    last = before;
    for (unsigned i = 0; i < 150; ++i) {
        usleep(100000);
        uint64_t current = atomic_load_explicit(ticks, memory_order_relaxed);
        if (current == last && current > before) {
            if (++unchanged >= 3) plateau = 1;
        } else {
            if (plateau && current > last) resumed_after_plateau = 1;
            unchanged = 0;
        }
        last = current;
    }
    after = atomic_load_explicit(ticks, memory_order_relaxed);
    stage = "child_release";
    if (write(release[1], "G", 1) != 1 ||
        waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status)) {
        error = ECHILD; goto done;
    }
    reaped = 1;
    if (after <= before || !plateau || !resumed_after_plateau) {
        error = EBUSY; goto done;
    }
    stage = "complete";
done:
    if (child > 0 && !reaped) {
        kill(child, SIGCONT);
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (release[0] >= 0) close(release[0]);
    if (release[1] >= 0) close(release[1]);
    if (ticks) munmap((void *)ticks, sizeof(*ticks));
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d child_pid=%d worker_progress=%d plateau=%d resumed_after_plateau=%d reaped=%d",
                  LAPY_PROBE_ID, stage, error, (int)child,
                  after > before, plateau, resumed_after_plateau, reaped);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
