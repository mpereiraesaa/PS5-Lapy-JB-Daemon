/* Native same-euid capability test. No direct kernel writes or elevation.
 * SDK/loader startup is outside the probe. Never dereference an old credential
 * after seteuid: the native operation may have freed it. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct snapshot {
    intptr_t credential, root, jail;
    uid_t uid, euid;
    gid_t gid, egid;
    uint64_t authority;
    uint8_t caps[16], attribute;
};

static int capture(struct snapshot *s, const char **stage)
{
    pid_t pid = getpid();
    memset(s, 0, sizeof(*s));
    *stage = "snapshot_credential";
    s->credential = kernel_get_proc_ucred(pid);
    if (!s->credential) return EFAULT;
    *stage = "snapshot_filedesc";
    intptr_t fd = kernel_get_proc_filedesc(pid);
    if (!fd) return EFAULT;
    /* A jail pointer may legitimately be NULL; distinguish a successful read
     * of NULL from an SDK convenience getter's failure sentinel. */
    *stage = "snapshot_root";
    if (kernel_copyout(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, &s->root, sizeof(s->root)))
        return EFAULT;
    *stage = "snapshot_jail";
    if (kernel_copyout(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, &s->jail, sizeof(s->jail)))
        return EFAULT;
    s->uid = getuid(); s->euid = geteuid();
    s->gid = getgid(); s->egid = getegid();
    *stage = "snapshot_authority";
    if (kernel_copyout(s->credential + KERNEL_OFFSET_UCRED_CR_SCEAUTHID,
                       &s->authority, sizeof(s->authority)))
        return EFAULT;
    *stage = "snapshot_caps";
    if (kernel_copyout(s->credential + KERNEL_OFFSET_UCRED_CR_SCECAPS,
                       s->caps, sizeof(s->caps)))
        return EFAULT;
    *stage = "snapshot_attribute";
    if (kernel_copyout(s->credential + KERNEL_OFFSET_UCRED_CR_SCEATTRS,
                       &s->attribute, sizeof(s->attribute)))
        return EFAULT;
    return 0;
}

static int equal_state(const struct snapshot *a, const struct snapshot *b)
{
    return a->uid == b->uid && a->euid == b->euid && a->gid == b->gid &&
           a->egid == b->egid && a->root == b->root && a->jail == b->jail &&
           a->authority == b->authority && a->attribute == b->attribute &&
           memcmp(a->caps, b->caps, sizeof(a->caps)) == 0;
}

int main(void)
{
    struct snapshot before, after;
    unsigned complete = 0, replacements = 0;
    int error = 0;
    const char *stage = "snapshot_before";
    if (ps5log_init_default("LAPYCRED", "lapy-credential-probe")) return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x cycles=64 mode=same-euid",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    error = capture(&before, &stage);
    if (error) goto done;
    while (complete < 64) {
        stage = "native_seteuid";
        if (seteuid(before.euid) < 0) { error = errno; goto done; }
        stage = "snapshot_after";
        error = capture(&after, &stage);
        if (error) goto done;
        stage = "preserved_state";
        if (!equal_state(&before, &after)) { error = EPROTO; goto done; }
        stage = "credential_replaced";
        if (before.credential == after.credential) { error = ENOTSUP; goto done; }
        ++replacements;
        ++complete;
        before = after;
    }
    stage = "complete";
done:
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d completed=%u replacements=%u expected=64",
                  LAPY_PROBE_ID, stage, error, complete, replacements);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
