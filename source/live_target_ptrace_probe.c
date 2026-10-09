/* One-shot title ptrace-retention and exit-lifetime observer. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <machine/reg.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SANDBOX_BASE "/mnt/sandbox"
#ifndef LAPY_TARGET_TITLE
#define LAPY_TARGET_TITLE "PPSA99995"
#endif
#define TITLE_PREFIX LAPY_TARGET_TITLE "_"
#define REQUEST_SUFFIX "/download0/etahen_jailbreak"
#define MAX_POLLS 600u
#define POLL_US 100000u
#define MAX_THREADS 256u
#define PROC_THREADS_HEAD 0x10u
#define PROC_PID_OFFSET 0xbcu
#define PROC_SUSPCOUNT 0x3a0u
#define THREAD_PROC 0x08u
#define THREAD_NEXT 0x10u
#define FD_REFCNT 0x34u
#define PTRACE_AUTHID UINT64_C(0x4800000000010003)
#ifndef LAPY_SCAN_GADGET
#define LAPY_SCAN_GADGET 0
#endif
#ifndef LAPY_EXIT_LIFETIME
#define LAPY_EXIT_LIFETIME 0
#endif
#ifndef LAPY_OBSERVE_STATE
#define LAPY_OBSERVE_STATE 0
#endif
#if LAPY_OBSERVE_STATE
#define FD_CDIR 0x08u
#define SYSTEM_AUTHID UINT64_C(0x4801000000000013)
extern intptr_t kernel_get_ucred_prison(pid_t pid);
#endif

struct target_snapshot {
    intptr_t proc, filedesc, credential;
    intptr_t threads[MAX_THREADS];
    unsigned count, suspended;
    uint32_t fd_refs;
#if LAPY_OBSERVE_STATE
    intptr_t root, jail, cwd, prison;
    uid_t uid, ruid, svuid;
    gid_t rgid;
    uint64_t authid, attrs;
    uint8_t caps[16];
#endif
};

static pid_t parse_request_pid(const char *message)
{
    const char *position = strstr(message, "\"PID\"");
    if (!position || !(position = strchr(position, ':'))) return -1;
    ++position;
    while (*position == ' ' || *position == '\t' || *position == '"') ++position;
    errno = 0;
    char *end = 0;
    long value = strtol(position, &end, 10);
    if (errno || end == position || value <= 1 || value > INT_MAX) return -1;
    return (pid_t)value;
}

static int find_request(char path[512], pid_t *pid, time_t started)
{
    DIR *directory = opendir(SANDBOX_BASE);
    if (!directory) return errno == ENOENT ? 0 : -(errno ? errno : EIO);
    struct dirent *entry;
    int result = 0;
    while ((entry = readdir(directory)) != 0) {
        if (strncmp(entry->d_name, TITLE_PREFIX,
                    sizeof(TITLE_PREFIX) - 1)) continue;
        int length = snprintf(path, 512, "%s/%s%s", SANDBOX_BASE,
                              entry->d_name, REQUEST_SUFFIX);
        if (length <= 0 || length >= 512) continue;
        struct stat st;
        if (stat(path, &st) || st.st_size <= 0 || st.st_mtime < started)
            continue;
        FILE *stream = fopen(path, "r");
        if (!stream) { result = -(errno ? errno : EIO); break; }
        char message[512];
        size_t size = fread(message, 1, sizeof(message) - 1, stream);
        int read_error = ferror(stream);
        fclose(stream);
        if (read_error || !size) { result = -EIO; break; }
        message[size] = 0;
        *pid = parse_request_pid(message);
        result = *pid > 1 ? 1 : -EINVAL;
        break;
    }
    closedir(directory);
    return result;
}

static int read_target(pid_t pid, struct target_snapshot *out)
{
    pid_t observed = 0;
    intptr_t current = 0, owner = 0, next = 0;
    memset(out, 0, sizeof(*out));
    out->proc = kernel_get_proc(pid);
    if (!out->proc ||
        kernel_copyout(out->proc + PROC_PID_OFFSET, &observed,
                       sizeof(observed)) || observed != pid) return ESRCH;
    out->filedesc = kernel_get_proc_filedesc(pid);
    out->credential = kernel_get_proc_ucred(pid);
    if (!out->filedesc || !out->credential ||
        kernel_copyout(out->filedesc + FD_REFCNT, &out->fd_refs,
                       sizeof(out->fd_refs)) ||
        kernel_copyout(out->proc + PROC_SUSPCOUNT, &out->suspended,
                       sizeof(out->suspended)) ||
        kernel_copyout(out->proc + PROC_THREADS_HEAD, &current,
                       sizeof(current))) return EFAULT;
#if LAPY_OBSERVE_STATE
    out->prison = kernel_get_ucred_prison(pid);
    if (!out->prison ||
        kernel_copyout(out->filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                       &out->root, sizeof(out->root)) ||
        kernel_copyout(out->filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                       &out->jail, sizeof(out->jail)) ||
        kernel_copyout(out->filedesc + FD_CDIR,
                       &out->cwd, sizeof(out->cwd))) return EFAULT;
    out->uid = kernel_get_ucred_uid(pid);
    out->ruid = kernel_get_ucred_ruid(pid);
    out->svuid = kernel_get_ucred_svuid(pid);
    out->rgid = kernel_get_ucred_rgid(pid);
    out->authid = kernel_get_ucred_authid(pid);
    out->attrs = kernel_get_ucred_attrs(pid);
    if (kernel_get_ucred_caps(pid, out->caps)) return EFAULT;
#endif
    while (current) {
        if (out->count >= MAX_THREADS) return EOVERFLOW;
        for (unsigned i = 0; i < out->count; ++i)
            if (out->threads[i] == current) return ELOOP;
        out->threads[out->count++] = current;
        if (kernel_copyout(current + THREAD_PROC, &owner, sizeof(owner)) ||
            kernel_copyout(current + THREAD_NEXT, &next, sizeof(next)) ||
            owner != out->proc) return EFAULT;
        current = next;
    }
    return out->count ? 0 : EPROTO;
}

#if LAPY_EXIT_LIFETIME
static int read_lifetime_target(pid_t pid, struct target_snapshot *out)
{
    pid_t observed = 0;
    memset(out, 0, sizeof(*out));
    out->proc = kernel_get_proc(pid);
    if (!out->proc ||
        kernel_copyout(out->proc + KERNEL_OFFSET_PROC_P_PID,
                       &observed, sizeof(observed)) || observed != pid)
        return ESRCH;
    out->filedesc = kernel_get_proc_filedesc(pid);
    out->credential = kernel_get_proc_ucred(pid);
    return !out->filedesc || !out->credential ||
           kernel_copyout(out->filedesc + FD_REFCNT, &out->fd_refs,
                          sizeof(out->fd_refs)) ? EFAULT : 0;
}
#endif

static int same_members(const struct target_snapshot *a,
                        const struct target_snapshot *b)
{
    int equal = a->proc == b->proc && a->filedesc == b->filedesc &&
           a->credential == b->credential &&
           a->count == b->count && a->fd_refs == b->fd_refs &&
           !memcmp(a->threads, b->threads,
                   a->count * sizeof(a->threads[0]));
#if LAPY_OBSERVE_STATE
    equal = equal && a->root == b->root && a->jail == b->jail &&
            a->cwd == b->cwd && a->prison == b->prison && a->uid == b->uid &&
            a->ruid == b->ruid && a->svuid == b->svuid &&
            a->rgid == b->rgid && a->authid == b->authid &&
            a->attrs == b->attrs &&
            !memcmp(a->caps, b->caps, sizeof(a->caps));
#endif
    return equal;
}

#if LAPY_EXIT_LIFETIME
static int reap_killed_target(pid_t pid, unsigned *polls)
{
    for (*polls = 0; *polls < 500; ++*polls) {
        int status = 0;
        pid_t observed = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (observed == pid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) return 0;
            if (WIFSTOPPED(status) &&
                ptrace(PT_CONTINUE, pid, (caddr_t)1, SIGKILL) &&
                errno != ESRCH) return errno ? errno : EIO;
        } else if (observed < 0) {
            return errno == ECHILD ? 0 : (errno ? errno : EIO);
        }
        usleep(10000);
    }
    return ETIMEDOUT;
}
#endif

#if LAPY_SCAN_GADGET
static int scan_syscall(pid_t pid, uintptr_t rip, uintptr_t *gadget,
                        uintptr_t *distance, int *from_libkernel,
                        unsigned *read_words)
{
    const uintptr_t page = rip & ~(uintptr_t)0xfffu;
    const uintptr_t libkernel_base = UINT64_C(0x800000000);
    uintptr_t starts[2] = {page >= 0x4000u ? page - 0x4000u : 0,
                           libkernel_base};
    uintptr_t ends[2] = {page + 0x5000u, libkernel_base + 0x1000u};
    if (ends[0] < page) return EOVERFLOW;
    for (unsigned region = 0; region < 2; ++region) {
        for (uintptr_t address = starts[region]; address < ends[region];
             address += sizeof(long)) {
            errno = 0;
            long word = ptrace(PT_READ_I, pid, (caddr_t)address, 0);
            if (word == -1 && errno) continue;
            ++*read_words;
            uint64_t bytes = (uint64_t)(unsigned long)word;
            for (unsigned offset = 0; offset < sizeof(long); ++offset) {
                if (((bytes >> (offset * 8)) & 0xffu) != 0x0fu) continue;
                uintptr_t candidate = address + offset;
                errno = 0;
                long instruction = ptrace(PT_READ_I, pid,
                                          (caddr_t)candidate, 0);
                if (instruction == -1 && errno) continue;
                if (((unsigned long)instruction & 0xffffu) != 0x050fu)
                    continue;
                *gadget = candidate;
                *from_libkernel = region == 1;
                *distance = region == 1 ? candidate - libkernel_base :
                            (candidate > rip ? candidate - rip :
                             rip - candidate);
                return 0;
            }
        }
    }
    return ENOENT;
}
#endif

int main(void)
{
    char path[512] = {0};
    pid_t pid = -1;
    time_t started = time(NULL);
    struct target_snapshot before, stopped_a, stopped_b, resumed;
    unsigned polls = 0, wait_polls = 0, threads = 0, suspended = 0;
    int error = 0, attached = 0, stopped = 0, detached = 0;
    int acknowledged = 0, private_fd = 0, stable_stop = 0;
    int auth_changed = 0, auth_restored = 0, private_self_cred = 0;
    intptr_t self_cred_before = 0, self_cred_after = 0;
    uint64_t original_authid = 0;
#if LAPY_EXIT_LIFETIME
    struct target_snapshot kill_queued_a, kill_queued_b;
    unsigned exit_polls = 0, reap_polls = 0;
    int external_kill_queued = 0, stopped_fd_retained = 0;
    int target_killed = 0, target_reaped = 0, retained_proc = 0;
    int fd_cleared = 0, ucred_cleared = 0;
#endif
#if LAPY_SCAN_GADGET
    struct reg registers = {0};
    uintptr_t gadget = 0, distance = 0;
    int from_libkernel = 0;
    unsigned read_words = 0;
#endif
    const char *stage = "preflight";

    if (ps5log_init_default("LAPYTP", "lapy-live-title-ptrace-retention"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=%s title=%s scan_gadget=%d max_polls=%u",
                  LAPY_PROBE_ID, kernel_get_fw_version(),
                  LAPY_EXIT_LIFETIME ? "live-title-exit-lifetime-read-only" :
                                       "live-title-ptrace-retention",
                  LAPY_TARGET_TITLE, LAPY_SCAN_GADGET, MAX_POLLS);
    if (KERNEL_OFFSET_PROC_P_PID != PROC_PID_OFFSET ||
        (!LAPY_EXIT_LIFETIME && kernel_get_fw_version() != 0x12020000)) {
        error = ENOTSUP; goto done;
    }
    stage = "find_request";
    for (; polls < MAX_POLLS; ++polls) {
        int found = find_request(path, &pid, started);
        if (found < 0) { error = -found; goto done; }
        if (found) break;
        usleep(POLL_US);
    }
    if (polls == MAX_POLLS) { error = ETIMEDOUT; goto done; }
    stage = "target_before";
#if LAPY_EXIT_LIFETIME
    if ((error = read_lifetime_target(pid, &before))) goto done;
#else
    if ((error = read_target(pid, &before))) goto done;
#endif
    if (before.fd_refs != 1 || before.suspended != 0) {
        error = EBUSY; goto done;
    }
    stage = "private_self_credential";
    self_cred_before = kernel_get_proc_ucred(getpid());
    original_authid = kernel_get_ucred_authid(getpid());
    if (!self_cred_before || !original_authid || seteuid(geteuid())) {
        error = errno ? errno : EPROTO; goto done;
    }
    self_cred_after = kernel_get_proc_ucred(getpid());
    private_self_cred = self_cred_after &&
                        self_cred_after != self_cred_before &&
                        kernel_get_ucred_authid(getpid()) == original_authid;
    if (!private_self_cred) { error = EPROTO; goto done; }
    auth_changed = 1;
    if (kernel_set_ucred_authid(getpid(), PTRACE_AUTHID) ||
        kernel_get_ucred_authid(getpid()) != PTRACE_AUTHID) {
        error = EACCES; goto done;
    }
    stage = "ptrace_attach";
    if (ptrace(PT_ATTACH, pid, 0, 0)) {
        error = errno ? errno : EIO; goto done;
    }
    attached = 1;
    stage = "wait_attach_stop";
    for (; wait_polls < 100; ++wait_polls) {
        int status = 0;
        pid_t observed = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (observed == pid) {
            if (!WIFSTOPPED(status)) { error = EPROTO; goto held; }
            stopped = 1;
            break;
        }
        if (observed < 0) { error = errno ? errno : ECHILD; goto held; }
        usleep(50000);
    }
    if (!stopped) { error = ETIMEDOUT; goto held; }
    stage = "verify_stopped";
#if LAPY_EXIT_LIFETIME
    if ((error = read_lifetime_target(pid, &stopped_a))) goto done;
    usleep(50000);
    if ((error = read_lifetime_target(pid, &stopped_b))) goto done;
#else
    if ((error = read_target(pid, &stopped_a))) goto done;
    usleep(50000);
    if ((error = read_target(pid, &stopped_b))) goto done;
#endif
    stable_stop = stopped_a.proc == before.proc &&
                  stopped_a.filedesc == before.filedesc &&
                  same_members(&stopped_a, &stopped_b) &&
                  stopped_b.count == stopped_b.suspended;
    threads = stopped_b.count;
    suspended = stopped_b.suspended;
    private_fd = stopped_b.fd_refs == 1;
    if (!stable_stop || !private_fd) { error = EBUSY; goto done; }
    ps5log_printf(PS5LOG_MARK,
                  "target_stopped build=%s private_self_cred=1 retained_identity=1 threads=%u suspended=%u private_fd=1",
                  LAPY_PROBE_ID, threads, suspended);
#if LAPY_EXIT_LIFETIME
    stage = "queue_external_kill";
    if (kill(pid, SIGKILL)) {
        error = errno ? errno : EIO; goto done;
    }
    external_kill_queued = 1;
    usleep(250000);
    if ((error = read_lifetime_target(pid, &kill_queued_a)) ||
        (error = read_lifetime_target(pid, &kill_queued_b))) goto done;
    stopped_fd_retained = kill_queued_a.proc == stopped_b.proc &&
                          kill_queued_a.filedesc == stopped_b.filedesc &&
                          kill_queued_a.credential == stopped_b.credential &&
                          kill_queued_a.fd_refs == stopped_b.fd_refs &&
                          kill_queued_b.proc == kill_queued_a.proc &&
                          kill_queued_b.filedesc == kill_queued_a.filedesc &&
                          kill_queued_b.credential == kill_queued_a.credential &&
                          kill_queued_b.fd_refs == kill_queued_a.fd_refs;
    ps5log_printf(stopped_fd_retained ? PS5LOG_MARK : PS5LOG_ERR,
                  "stopped_kill_guard build=%s external_kill_queued=1 fd_retained=%d",
                  LAPY_PROBE_ID, stopped_fd_retained);
    if (!stopped_fd_retained) { error = EBUSY; goto done; }
    stage = "resume_killed_target";
    if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0)) {
        error = errno ? errno : EIO; goto done;
    }
    target_killed = 1;
    stopped = 0;
    stage = "observe_exit_lifetime";
    for (; exit_polls < 5000; ++exit_polls) {
        pid_t observed_pid = 0;
        intptr_t current_fd = -1, current_ucred = -1;
        if (kernel_copyout(before.proc + KERNEL_OFFSET_PROC_P_PID,
                           &observed_pid, sizeof(observed_pid)) ||
            kernel_copyout(before.proc + KERNEL_OFFSET_PROC_P_FD,
                           &current_fd, sizeof(current_fd)) ||
            kernel_copyout(before.proc + KERNEL_OFFSET_PROC_P_UCRED,
                           &current_ucred, sizeof(current_ucred))) {
            error = EFAULT; goto done;
        }
        retained_proc = observed_pid == pid;
        fd_cleared = current_fd == 0;
        ucred_cleared = current_ucred == 0;
        if (retained_proc && fd_cleared) break;
        usleep(1000);
    }
    if (!retained_proc || !fd_cleared) { error = ETIMEDOUT; goto done; }
    ps5log_printf(PS5LOG_MARK,
                  "target_exit_lifetime build=%s retained_proc=1 private_fd_before=1 fd_cleared=1 ucred_cleared=%d polls=%u",
                  LAPY_PROBE_ID, ucred_cleared, exit_polls);
    error = reap_killed_target(pid, &reap_polls);
    if (error) goto done;
    target_reaped = 1;
    attached = 0;
#endif
#if LAPY_SCAN_GADGET
    stage = "scan_gadget";
    if (ptrace(PT_GETREGS, pid, (caddr_t)&registers, 0)) {
        error = errno ? errno : EIO; goto done;
    }
    errno = 0;
    long text_f8 = ptrace(PT_READ_I, pid,
                          (caddr_t)UINT64_C(0x8000000f8), 0);
    int text_errno = errno;
    errno = 0;
    long data_f8 = ptrace(PT_READ_D, pid,
                          (caddr_t)UINT64_C(0x8000000f8), 0);
    int data_errno = errno;
    ps5log_printf(PS5LOG_MARK,
                  "read_diag build=%s text_low=%08lx text_errno=%d data_low=%08lx data_errno=%d",
                  LAPY_PROBE_ID, (unsigned long)text_f8 & 0xffffffffu,
                  text_errno, (unsigned long)data_f8 & 0xffffffffu,
                  data_errno);
    error = scan_syscall(pid, (uintptr_t)registers.r_rip,
                         &gadget, &distance, &from_libkernel, &read_words);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "gadget_scan build=%s found=%d distance=%lu verified=%d libkernel=%d read_words=%u",
                  LAPY_PROBE_ID, !error, (unsigned long)distance,
                  !error && gadget != 0, from_libkernel, read_words);
    if (error) goto done;
#endif
    stage = "complete";
done:
#if LAPY_EXIT_LIFETIME
    if (attached && target_killed) {
        int reap_error = reap_killed_target(pid, &reap_polls);
        if (!reap_error) { target_reaped = 1; attached = 0; }
        else if (!error) error = reap_error;
    }
#endif
#if LAPY_EXIT_LIFETIME
    if (attached && !target_killed) {
#else
    if (attached) {
#endif
        if (!stopped) goto held;
        if (ptrace(PT_DETACH, pid, (caddr_t)1, 0)) {
            error = errno ? errno : EIO;
            goto held;
        }
        attached = 0;
        detached = 1;
        if (kill(pid, SIGCONT) && !error) error = errno ? errno : EIO;
        if (!error) {
            usleep(50000);
            if (read_target(pid, &resumed) ||
                resumed.proc != before.proc || resumed.suspended != 0)
                error = EPROTO;
        }
    }
    if (auth_changed) {
        if (!kernel_set_ucred_authid(getpid(), original_authid) &&
            kernel_get_ucred_authid(getpid()) == original_authid)
            auth_restored = 1;
        else if (!error) error = EIO;
    }
    if (path[0]) {
        if (!unlink(path)) acknowledged = 1;
        else if (LAPY_EXIT_LIFETIME && errno == ENOENT) acknowledged = 1;
        else if (!error) error = errno ? errno : EIO;
    }
#if LAPY_EXIT_LIFETIME
    ps5log_printf((retained_proc && fd_cleared && target_reaped) ?
                  PS5LOG_MARK : PS5LOG_ERR,
                  "exit_lifetime_result build=%s external_kill_queued=%d stopped_fd_retained=%d killed=%d retained_proc=%d fd_cleared=%d ucred_cleared=%d reaped=%d exit_polls=%u reap_polls=%u",
                  LAPY_PROBE_ID, external_kill_queued, stopped_fd_retained,
                  target_killed, retained_proc, fd_cleared, ucred_cleared,
                  target_reaped, exit_polls, reap_polls);
#endif
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d polls=%u wait_polls=%u target_pid=%d attached=%d detached=%d acknowledged=%d threads=%u suspended=%u stable_stop=%d private_fd=%d private_self_cred=%d auth_restored=%d",
                  LAPY_PROBE_ID, stage, error, polls, wait_polls, (int)pid,
                  attached, detached, acknowledged, threads, suspended,
                  stable_stop, private_fd, private_self_cred, auth_restored);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
held:
    ps5log_printf(PS5LOG_ERR,
                  "probe_held build=%s stage=%s error=%d target_pid=%d attached=%d stopped=%d",
                  LAPY_PROBE_ID, stage, error, (int)pid, attached, stopped);
    for (;;) sleep(1);
}
