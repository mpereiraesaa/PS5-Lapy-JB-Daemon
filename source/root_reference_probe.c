/* Read-only root-vnode reference observer. It deliberately does not change a
 * credential, filedesc, vnode, syscall table, or any process other than itself.
 * Field positions are observations, not trusted firmware offsets. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define SNAPSHOT_BYTES 0x1c4u /* includes SDK-header hints 0x1bc/0x1c0 */
#define SNAPSHOT_WORDS (SNAPSHOT_BYTES / sizeof(uint32_t))
#define SAMPLES 120u
#define PERIOD_US 1000000u

/* These offsets are compiled from the SDK's FreeBSD vnode header, not
 * authenticated against any PS5 firmware. Never write through them. */
#define HINT_HOLD 0x1bcu
#define HINT_USE  0x1c0u

static int get_root_vnode(intptr_t *root, const char **stage)
{
    *root = 0;
    *stage = "root_data";
    if (KERNEL_ADDRESS_ROOTVNODE) {
        *root = kernel_get_root_vnode();
        if (*root) return 0;
    }

    /* The SDK's per-firmware root symbol may be absent. Init's own root
     * directory is a read-only fallback, never an offset guessed for a FW. */
    *stage = "init_filedesc";
    intptr_t fd = kernel_get_proc_filedesc(1);
    if (!fd) return ENOTSUP;
    *stage = "init_root";
    if (kernel_copyout(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                       root, sizeof(*root)) || !*root)
        return EFAULT;
    return 0;
}

static int snapshot(intptr_t root, uint32_t *values)
{
    return kernel_copyout(root, values, SNAPSHOT_BYTES) ? EFAULT : 0;
}

static int plausible(uint32_t value)
{
    return value > 0 && value <= 4096;
}

int main(void)
{
    uint32_t previous[SNAPSHOT_WORDS], current[SNAPSHOT_WORDS];
    intptr_t root = 0;
    const char *stage = "logging";
    unsigned sampled = 0, changes = 0;
    int error = 0;

    if (ps5log_init_default("LAPYREF", "lapy-root-reference-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x samples=%u period_us=%u mode=read-only",
                  LAPY_PROBE_ID, kernel_get_fw_version(), SAMPLES, PERIOD_US);
    error = get_root_vnode(&root, &stage);
    if (error) goto done;
    stage = "snapshot_first";
    error = snapshot(root, previous);
    if (error) goto done;
    ++sampled;
    if (plausible(previous[HINT_HOLD / 4]) &&
        plausible(previous[HINT_USE / 4])) {
        ps5log_printf(PS5LOG_MARK,
                      "reference_hints build=%s sample=0 hold_offset=0x%x hold=%u use_offset=0x%x use=%u status=plausible-unverified",
                      LAPY_PROBE_ID, HINT_HOLD, previous[HINT_HOLD / 4],
                      HINT_USE, previous[HINT_USE / 4]);
    } else {
        /* An SDK hint could land on a pointer field in Sony's vnode layout.
         * Publish no value when its interpretation as a small count fails. */
        ps5log_printf(PS5LOG_MARK,
                      "reference_hints build=%s sample=0 hold_offset=0x%x use_offset=0x%x status=unavailable",
                      LAPY_PROBE_ID, HINT_HOLD, HINT_USE);
    }

    for (unsigned sample = 1; sample < SAMPLES; ++sample) {
        usleep(PERIOD_US);
        stage = "root_stability";
        intptr_t again = 0;
        error = get_root_vnode(&again, &stage);
        if (error) goto done;
        if (again != root) { error = ESTALE; goto done; }
        stage = "snapshot_next";
        error = snapshot(root, current);
        if (error) goto done;
        ++sampled;
        /* Print only changed small nonzero 32-bit fields, so the probe does
         * not transmit kernel pointers or dump unrelated vnode contents.
         * Correlation with a separate escalation log is required. */
        for (unsigned word = 0; word < SNAPSHOT_WORDS; ++word) {
            uint32_t a = previous[word], b = current[word];
            if (a != b && plausible(a) && plausible(b)) {
                int64_t delta = (int64_t)b - (int64_t)a;
                if (delta >= -8 && delta <= 8) {
                    ps5log_printf(PS5LOG_MARK,
                                  "candidate_change build=%s sample=%u offset=0x%x before=%u after=%u delta=%ld",
                                  LAPY_PROBE_ID, sample, word * 4, a, b, (long)delta);
                    ++changes;
                }
            }
        }
        memcpy(previous, current, sizeof(previous));
    }
    stage = "complete";
done:
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d sampled=%u changes=%u expected=%u",
                  LAPY_PROBE_ID, stage, error, sampled, changes, SAMPLES);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
