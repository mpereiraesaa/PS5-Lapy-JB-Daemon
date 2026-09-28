/* One-shot FW 12.02 title stop observer. No kernel writes or elevation. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

struct target_snapshot {
    intptr_t proc, filedesc;
    intptr_t threads[MAX_THREADS];
    unsigned count, suspended;
    uint32_t fd_refs;
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
    if (!out->filedesc ||
        kernel_copyout(out->filedesc + FD_REFCNT, &out->fd_refs,
                       sizeof(out->fd_refs)) ||
        kernel_copyout(out->proc + PROC_SUSPCOUNT, &out->suspended,
                       sizeof(out->suspended)) ||
        kernel_copyout(out->proc + PROC_THREADS_HEAD, &current,
                       sizeof(current))) return EFAULT;
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

static int same_members(const struct target_snapshot *a,
                        const struct target_snapshot *b)
{
    return a->proc == b->proc && a->filedesc == b->filedesc &&
           a->count == b->count && a->fd_refs == b->fd_refs &&
           !memcmp(a->threads, b->threads,
                   a->count * sizeof(a->threads[0]));
}

int main(void)
{
    char path[512] = {0};
    pid_t pid = -1;
    time_t started = time(NULL);
    struct target_snapshot before, stopped_a, stopped_b, resumed;
    unsigned polls = 0, stop_polls = 0, threads = 0, suspended = 0;
    int error = 0, stop_sent = 0, resume_sent = 0, acknowledged = 0;
    int private_fd = 0, stable_stop = 0;
    const char *stage = "preflight";

    if (ps5log_init_default("LAPYTS", "lapy-live-target-stop-probe")) return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=live-title-stop-read-only title=%s max_polls=%u",
                  LAPY_PROBE_ID, kernel_get_fw_version(), LAPY_TARGET_TITLE, MAX_POLLS);
    if (kernel_get_fw_version() != 0x12020000 ||
        KERNEL_OFFSET_PROC_P_PID != PROC_PID_OFFSET) {
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
    if ((error = read_target(pid, &before))) goto done;
    if (before.fd_refs != 1 || before.suspended != 0) {
        error = EBUSY; goto done;
    }
    stage = "send_stop";
    if (kill(pid, SIGSTOP)) { error = errno ? errno : EIO; goto done; }
    stop_sent = 1;
    stage = "wait_stopped";
    for (; stop_polls < 100; ++stop_polls) {
        if ((error = read_target(pid, &stopped_a))) goto done;
        if (stopped_a.proc != before.proc ||
            stopped_a.filedesc != before.filedesc) {
            error = ESTALE; goto done;
        }
        if (stopped_a.count == stopped_a.suspended) break;
        usleep(50000);
    }
    if (stop_polls == 100) { error = ETIMEDOUT; goto done; }
    usleep(50000);
    stage = "verify_stopped";
    if ((error = read_target(pid, &stopped_b))) goto done;
    stable_stop = same_members(&stopped_a, &stopped_b) &&
                  stopped_b.count == stopped_b.suspended;
    threads = stopped_b.count;
    suspended = stopped_b.suspended;
    private_fd = stopped_b.fd_refs == 1;
    if (!stable_stop || !private_fd) { error = EBUSY; goto done; }
    stage = "complete";
done:
    if (stop_sent) {
        if (!kill(pid, SIGCONT)) {
            resume_sent = 1;
            if (!error) {
                usleep(50000);
                if (read_target(pid, &resumed) ||
                    resumed.proc != before.proc || resumed.suspended != 0)
                    error = EPROTO;
            }
        } else if (!error) error = errno ? errno : EIO;
    }
    if (path[0]) {
        if (!unlink(path)) acknowledged = 1;
        else if (!error) error = errno ? errno : EIO;
    }
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d polls=%u stop_polls=%u target_pid=%d stop_sent=%d resume_sent=%d acknowledged=%d threads=%u suspended=%u stable_stop=%d private_fd=%d",
                  LAPY_PROBE_ID, stage, error, polls, stop_polls, (int)pid,
                  stop_sent, resume_sent, acknowledged, threads, suspended,
                  stable_stop, private_fd);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
