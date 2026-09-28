/* One-shot observer for a real Lapy request before legacy elevation.
 * It reports only directory relationships and a read-only filedesc hint,
 * acknowledges the request without elevating, and exits within 60 seconds. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SANDBOX_BASE "/mnt/sandbox"
#define EXPECTED_TITLE "PPSA99995_"
#define REQUEST_SUFFIX "/download0/etahen_jailbreak"
#define MAX_POLLS 600u
#define POLL_US 100000u

struct directory_snapshot {
    intptr_t filedesc, root, jail;
    uint32_t ref_hint;
};

static int get_system_root(intptr_t *root)
{
    *root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (*root) return 0;
    intptr_t init_fd = kernel_get_proc_filedesc(1);
    if (!init_fd || kernel_copyout(init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                                   root, sizeof(*root)) || !*root)
        return ENOTSUP;
    return 0;
}

static int read_snapshot(pid_t pid, struct directory_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    out->filedesc = kernel_get_proc_filedesc(pid);
    if (!out->filedesc) return ESRCH;
    if (kernel_copyout(out->filedesc + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                       &out->root, sizeof(out->root)) ||
        kernel_copyout(out->filedesc + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                       &out->jail, sizeof(out->jail))) return EFAULT;
    if (kernel_get_fw_version() == 0x12020000 &&
        kernel_copyout(out->filedesc + 0x34, &out->ref_hint,
                       sizeof(out->ref_hint))) return EFAULT;
    return 0;
}

static pid_t parse_request_pid(const char *message)
{
    const char *position = strstr(message, "\"PID\"");
    if (!position || !(position = strchr(position, ':'))) return -1;
    ++position;
    while (*position == ' ' || *position == '\t' || *position == '"') ++position;
    errno = 0;
    char *end = 0;
    long value = strtol(position, &end, 10);
    if (errno || end == position || value <= 1 || value > INT_MAX)
        return -1;
    return (pid_t)value;
}

static int find_request(char path[512], pid_t *pid, time_t started)
{
    DIR *directory = opendir(SANDBOX_BASE);
    if (!directory) return errno == ENOENT ? 0 : -(errno ? errno : EIO);
    struct dirent *entry;
    int result = 0;
    while ((entry = readdir(directory)) != 0) {
        if (strncmp(entry->d_name, EXPECTED_TITLE,
                    sizeof(EXPECTED_TITLE) - 1) != 0) continue;
        int length = snprintf(path, 512, "%s/%s%s", SANDBOX_BASE,
                              entry->d_name, REQUEST_SUFFIX);
        if (length <= 0 || length >= 512) continue;
        struct stat st;
        if (stat(path, &st) || st.st_size <= 0 ||
            st.st_mtime < started) continue;
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

int main(void)
{
    char path[512] = {0};
    pid_t pid = -1;
    intptr_t system_root = 0;
    struct directory_snapshot first, second;
    const char *stage = "find_request";
    int error = 0, stable = 0, acknowledged = 0;
    unsigned polls = 0;
    time_t started = time(NULL);

    if (ps5log_init_default("LAPYREQ", "lapy-live-request-directory-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x mode=request-read-only max_polls=%u",
                  LAPY_PROBE_ID, kernel_get_fw_version(), MAX_POLLS);
    error = get_system_root(&system_root);
    if (error) goto done;
    for (; polls < MAX_POLLS; ++polls) {
        int found = find_request(path, &pid, started);
        if (found < 0) { error = -found; goto done; }
        if (found) break;
        usleep(POLL_US);
    }
    if (polls == MAX_POLLS) { error = ETIMEDOUT; goto done; }
    stage = "first_snapshot";
    error = read_snapshot(pid, &first);
    if (error) goto acknowledge;
    usleep(10000);
    stage = "second_snapshot";
    error = read_snapshot(pid, &second);
    if (error) goto acknowledge;
    stage = "stability";
    stable = first.filedesc == second.filedesc &&
             first.root == second.root && first.jail == second.jail &&
             first.ref_hint == second.ref_hint;
    if (!stable) error = ESTALE;
acknowledge:
    /* Removing the marker is the existing app protocol's completion signal.
     * This probe never claims successful elevation; the app may reject /data. */
    if (!unlink(path)) acknowledged = 1;
    else if (!error) error = errno ? errno : EIO;
    if (!error) stage = "complete";
done:
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d polls=%u target_pid=%d stable=%d acknowledged=%d root_null=%d root_system=%d jail_null=%d jail_system=%d root_jail_same=%d ref_hint=%u ref_hint_valid=%d",
                  LAPY_PROBE_ID, stage, error, polls, (int)pid, stable,
                  acknowledged, !error && second.root == 0,
                  !error && second.root == system_root,
                  !error && second.jail == 0,
                  !error && second.jail == system_root,
                  !error && second.root == second.jail,
                  !error ? second.ref_hint : 0,
                  !error && kernel_get_fw_version() == 0x12020000 &&
                  second.ref_hint > 0 && second.ref_hint <= 4096);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
