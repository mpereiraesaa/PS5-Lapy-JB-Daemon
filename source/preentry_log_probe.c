/* One-shot FW 12.02 diagnostic log snapshot for a title that exits before
 * its own ps5log/1 initialization. Temporarily changes only this payload's
 * private credential; no target process is touched. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint64_t sceKernelDebugGetLogBufferSize(void) __asm__("C49jelxiaVE");
int sceKernelDebugGetSdkLogText(void *buffer, size_t buffer_size,
                               char **text, uint64_t *text_size);
int sceKernelDebugGetPrivateLogText(void *buffer, size_t buffer_size,
                                   char **text, uint64_t *text_size);

#define MAX_BUFFER (2u * 1024u * 1024u)
#define MAX_LINE 512u
#define MAX_MATCHES 80u
#define SCE_AUTHID_COREDUMP 0x4800000000000006ull

static int relevant(const char *line)
{
    return strstr(line, "PPSA99995") != 0 ||
           strstr(line, "pid=977") != 0 ||
           strstr(line, "pid=984") != 0 ||
           strstr(line, "exception:") != 0 ||
           strstr(line, "fault:") != 0 ||
           strstr(line, "rtld") != 0;
}

static void emit_line(const char *kind, const char *line, unsigned *matches)
{
    if (!*line || !relevant(line) || *matches >= MAX_MATCHES) return;
    ps5log_printf(PS5LOG_MARK, "log_match build=%s source=%s text=%s",
                  LAPY_PROBE_ID, kind, line);
    ++*matches;
}

static int snapshot(const char *kind,
                    int (*fetch)(void *, size_t, char **, uint64_t *),
                    void *buffer, size_t capacity, unsigned *matches)
{
    char *start = 0;
    uint64_t length = 0;
    int result = fetch(buffer, capacity, &start, &length);
    ps5log_printf(PS5LOG_MARK,
                  "log_source build=%s source=%s result=%d bytes=%llu",
                  LAPY_PROBE_ID, kind, result,
                  (unsigned long long)length);
    if (result < 0) return result;
    if (!start || !length) return 0;
    uintptr_t base = (uintptr_t)buffer, begin = (uintptr_t)start;
    if (begin < base || begin > base + capacity ||
        length > capacity - (begin - base)) return EPROTO;
    char line[MAX_LINE];
    size_t used = 0;
    for (uint64_t i = 0; i < length; ++i) {
        char ch = start[i];
        if (ch == '\n' || ch == '\r') {
            line[used] = 0;
            emit_line(kind, line, matches);
            used = 0;
        } else if (used + 1 < sizeof(line)) {
            line[used++] = ch;
        }
    }
    if (used) {
        line[used] = 0;
        emit_line(kind, line, matches);
    }
    return 0;
}

int main(void)
{
    unsigned matches = 0;
    int sdk_result = 0, private_result = 0;
    int privilege_error = 0, restored = 0, changed_authid = 0;
    uint64_t raw_size;
    void *buffer = 0;
    pid_t self = getpid();
    intptr_t old_cred = 0, private_cred = 0;
    uint64_t old_authid = 0;
    uint8_t old_caps[16] = {0}, all_caps[16], check_caps[16];
    if (ps5log_init_default("LAPYCRASH", "lapy-preentry-log-probe"))
        return 2;
    raw_size = sceKernelDebugGetLogBufferSize();
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s raw_buffer_size=%llu mode=read-only-snapshot",
                  LAPY_PROBE_ID, (unsigned long long)raw_size);
    if (!raw_size || raw_size > MAX_BUFFER) {
        privilege_error = ENOTSUP;
        goto done;
    }
    buffer = malloc((size_t)raw_size);
    if (!buffer) { privilege_error = ENOMEM; goto done; }
    old_cred = kernel_get_proc_ucred(self);
    old_authid = kernel_get_ucred_authid(self);
    if (!old_cred || kernel_get_ucred_caps(self, old_caps)) {
        privilege_error = EFAULT; goto done;
    }
    if (seteuid(geteuid())) { privilege_error = errno; goto done; }
    private_cred = kernel_get_proc_ucred(self);
    if (!private_cred || private_cred == old_cred ||
        kernel_get_ucred_authid(self) != old_authid ||
        kernel_get_ucred_caps(self, check_caps) ||
        memcmp(check_caps, old_caps, sizeof(old_caps))) {
        privilege_error = EPROTO; goto done;
    }
    memset(all_caps, 0xff, sizeof(all_caps));
    changed_authid = 1;
    if (kernel_set_ucred_authid(self, SCE_AUTHID_COREDUMP)) {
        privilege_error = EACCES; goto restore;
    }
    if (kernel_set_ucred_caps(self, all_caps)) {
        privilege_error = EACCES; goto restore;
    }
    sdk_result = snapshot("sdk", sceKernelDebugGetSdkLogText,
                          buffer, (size_t)raw_size, &matches);
    private_result = snapshot("private", sceKernelDebugGetPrivateLogText,
                              buffer, (size_t)raw_size, &matches);
restore:
    if (changed_authid) {
        if (kernel_set_ucred_caps(self, old_caps) ||
            kernel_set_ucred_authid(self, old_authid) ||
            kernel_get_ucred_authid(self) != old_authid ||
            kernel_get_ucred_caps(self, check_caps) ||
            memcmp(check_caps, old_caps, sizeof(old_caps)))
            privilege_error = EFAULT;
        else
            restored = 1;
    }
done:
    free(buffer);
    int failed = privilege_error || (sdk_result && private_result);
    ps5log_printf(failed ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s sdk_result=%d private_result=%d matches=%u privilege_error=%d private_cred=%d restored=%d",
                  LAPY_PROBE_ID, sdk_result, private_result, matches,
                  privilege_error, private_cred && private_cred != old_cred,
                  restored);
    ps5log_close(failed ? "probe-failed" :
                 "probe-complete");
    return failed ? 1 : 0;
}
