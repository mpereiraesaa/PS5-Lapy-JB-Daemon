/* Disposable-process capability test. It never changes another process or
 * writes kernel memory. This verifies PS5's native rfork filedesc behavior,
 * not whether Lapy can safely invoke it inside a future target. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include "filedesc_refcount.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_TIMEOUT_SECONDS 15u
#define SNAPSHOT_BYTES 0x80u

static int snapshot(intptr_t *filedesc, uint8_t bytes[SNAPSHOT_BYTES])
{
    *filedesc = kernel_get_proc_filedesc(getpid());
    if (!*filedesc) return ENOENT;
    if (kernel_copyout(*filedesc, bytes, SNAPSHOT_BYTES)) return EFAULT;
    return 0;
}

int main(void)
{
    intptr_t before = 0, shared = 0, private_fd = 0;
    int initial_refs = -1, shared_refs = -1, private_refs = -1;
    int old_refs = -1, error = 0, wait_status = 0;
    uint8_t initial_bytes[SNAPSHOT_BYTES], shared_bytes[SNAPSHOT_BYTES];
    uint8_t private_bytes[SNAPSHOT_BYTES], old_bytes[SNAPSHOT_BYTES];
    int release_pipe[2] = {-1, -1};
    void (*previous_sigpipe)(int) = SIG_ERR;
    const char *stage = "baseline";
    pid_t child = -1;
    int unshared = 0;
    unsigned candidate_count = 0, ref_offset = 0, ref_width = 0;

    if (ps5log_init_default("LAPYFD", "lapy-filedesc-unshare-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=self-only scan_bytes=%u",
                  LAPY_PROBE_ID, kernel_get_fw_version(), SNAPSHOT_BYTES);
    error = snapshot(&before, initial_bytes);
    if (error) goto done;
    if (pipe(release_pipe)) { error = errno ? errno : EIO; goto done; }
    previous_sigpipe = signal(SIGPIPE, SIG_IGN);
    if (previous_sigpipe == SIG_ERR) {
        error = errno ? errno : EIO;
        goto done;
    }

    stage = "create_shared_child";
    child = rfork(RFPROC);
    if (child == 0) {
        char release = 0;
        alarm(CHILD_TIMEOUT_SECONDS);
        _exit(read(release_pipe[0], &release, 1) == 1 ? 0 : 1);
    }
    if (child < 0) { error = errno ? errno : EIO; goto done; }

    stage = "shared_snapshot";
    error = snapshot(&shared, shared_bytes);
    if (error) goto done;
    if (shared != before) { error = EPROTO; goto done; }
    stage = "native_unshare";
    if (rfork(RFFDG) < 0) { error = errno ? errno : EIO; goto done; }
    stage = "private_snapshot";
    error = snapshot(&private_fd, private_bytes);
    if (error) goto done;
    if (kernel_copyout(shared, old_bytes, SNAPSHOT_BYTES)) {
        error = EFAULT;
        goto done;
    }
    stage = "calibrate_refcount";
    error = lapy_calibrate_filedesc_refcount(initial_bytes, shared_bytes,
                                             old_bytes, SNAPSHOT_BYTES,
                                             &ref_offset, &ref_width);
    if (error) goto done;
    candidate_count = 1;
    uint32_t initial_value = 0, shared_value = 0;
    uint32_t private_value = 0, old_value = 0;
    if (lapy_read_filedesc_refcount(initial_bytes, SNAPSHOT_BYTES,
                                   ref_offset, ref_width, &initial_value) ||
        lapy_read_filedesc_refcount(shared_bytes, SNAPSHOT_BYTES,
                                   ref_offset, ref_width, &shared_value) ||
        lapy_read_filedesc_refcount(private_bytes, SNAPSHOT_BYTES,
                                   ref_offset, ref_width, &private_value) ||
        lapy_read_filedesc_refcount(old_bytes, SNAPSHOT_BYTES,
                                   ref_offset, ref_width, &old_value)) {
        error = EPROTO; goto done;
    }
    initial_refs = (int)initial_value;
    shared_refs = (int)shared_value;
    private_refs = (int)private_value;
    old_refs = (int)old_value;
    unshared = private_fd != shared && private_refs == 1 && old_refs == 1;
    if (!unshared) error = EPROTO;

done:
    if (child > 0) {
        const char release = 1;
        if (write(release_pipe[1], &release, 1) != 1 && !error)
            error = EPIPE;
        stage = error ? stage : "wait_child";
        if (waitpid(child, &wait_status, 0) != child ||
            !WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
            if (!error) error = ECHILD;
        }
    }
    if (release_pipe[0] >= 0) close(release_pipe[0]);
    if (release_pipe[1] >= 0) close(release_pipe[1]);
    if (previous_sigpipe != SIG_ERR) signal(SIGPIPE, previous_sigpipe);
    /* Only equivalence and bounded reference counts leave the console. */
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d candidate_count=%u ref_offset=0x%x ref_width=%u initial_refs=%d shared_refs=%d private_refs=%d old_refs=%d shared_same=%d private_new=%d unshared=%d",
                  LAPY_PROBE_ID, stage, error, candidate_count, ref_offset,
                  ref_width, initial_refs, shared_refs, private_refs,
                  old_refs, shared == before,
                  private_fd != shared, unshared);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
