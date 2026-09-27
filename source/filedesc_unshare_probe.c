/* Disposable-process capability test. It never changes another process or
 * writes kernel memory. This verifies PS5's native rfork filedesc behavior,
 * not whether Lapy can safely invoke it inside a future target. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <stddef.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <sys/filedesc.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_TIMEOUT_SECONDS 15u

static int snapshot(intptr_t *filedesc, int *refs)
{
    *filedesc = kernel_get_proc_filedesc(getpid());
    if (!*filedesc) return ENOENT;
    if (kernel_copyout(*filedesc + offsetof(struct filedesc, fd_refcnt),
                       refs, sizeof(*refs))) return EFAULT;
    return 0;
}

int main(void)
{
    intptr_t before = 0, shared = 0, private_fd = 0;
    int initial_refs = -1, shared_refs = -1, private_refs = -1;
    int old_refs = -1, error = 0, wait_status = 0;
    int release_pipe[2] = {-1, -1};
    const char *stage = "baseline";
    pid_t child = -1;
    int unshared = 0;

    if (ps5log_init_default("LAPYFD", "lapy-filedesc-unshare-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=self-only ref_offset=0x%zx",
                  LAPY_PROBE_ID, kernel_get_fw_version(),
                  offsetof(struct filedesc, fd_refcnt));
    error = snapshot(&before, &initial_refs);
    if (error) goto done;
    if (initial_refs != 1) { error = EBUSY; goto done; }
    if (pipe(release_pipe)) { error = errno ? errno : EIO; goto done; }

    stage = "create_shared_child";
    child = rfork(RFPROC);
    if (child == 0) {
        char release = 0;
        alarm(CHILD_TIMEOUT_SECONDS);
        _exit(read(release_pipe[0], &release, 1) == 1 ? 0 : 1);
    }
    if (child < 0) { error = errno ? errno : EIO; goto done; }

    stage = "shared_snapshot";
    error = snapshot(&shared, &shared_refs);
    if (error) goto done;
    if (shared != before || shared_refs != 2) { error = EPROTO; goto done; }

    stage = "native_unshare";
    if (rfork(RFFDG) < 0) { error = errno ? errno : EIO; goto done; }
    stage = "private_snapshot";
    error = snapshot(&private_fd, &private_refs);
    if (error) goto done;
    if (kernel_copyout(shared + offsetof(struct filedesc, fd_refcnt),
                       &old_refs, sizeof(old_refs))) { error = EFAULT; goto done; }
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
    /* Only equivalence and bounded reference counts leave the console. */
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d initial_refs=%d shared_refs=%d private_refs=%d old_refs=%d shared_same=%d private_new=%d unshared=%d",
                  LAPY_PROBE_ID, stage, error, initial_refs, shared_refs,
                  private_refs, old_refs, shared == before,
                  private_fd != shared, unshared);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
