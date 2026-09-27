/* Read-only syscall-table classification. Never read executable kernel text,
 * invoke a kernel function pointer, or publish kernel addresses. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>

struct entry { int32_t arguments; uint32_t padding; uint64_t call; };
_Static_assert(sizeof(struct entry) == 16, "sysent prefix ABI");

int main(void)
{
    const unsigned numbers[] = {0, 8, 11, 13, 20, 23, 61, 183};
    struct entry entries[sizeof(numbers) / sizeof(numbers[0])];
    int error = 0;
    const char *stage = "firmware_anchor";
    if (ps5log_init_default("LAPYSYS", "lapy-sysent-probe")) return 2;
    ps5log_printf(PS5LOG_MARK, "probe_start build=%s firmware=%08x mode=sysent-read-only",
                  LAPY_PROBE_ID, kernel_get_fw_version());
    /* Pinned kstuff-lite 33ec81e, prosper0gdb/offsets/12_02.h; SDK provides the
     * independent allproc anchor. FreeBSD sysent layout is 48 bytes, call +8. */
    if (kernel_get_fw_version() != 0x12020000 || !KERNEL_ADDRESS_DATA_BASE ||
        KERNEL_ADDRESS_ALLPROC != KERNEL_ADDRESS_DATA_BASE + 0x2885e00) {
        error = EPROTONOSUPPORT; goto done;
    }
    stage = "table_read";
    for (unsigned i = 0; i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
        intptr_t address = KERNEL_ADDRESS_DATA_BASE + 0x1af4d0 + numbers[i] * 48;
        if (kernel_copyout(address, &entries[i], sizeof(entries[i]))) {
            error = EFAULT; goto done;
        }
        if ((entries[i].call >> 48) != UINT64_C(0xffff) ||
            entries[i].arguments < 0 || entries[i].arguments > 16) {
            error = EPROTO; goto done;
        }
    }
    stage = "layout_controls";
    if (entries[3].arguments != 1 || entries[4].arguments != 0 ||
        entries[5].arguments != 1 || entries[7].arguments != 1) {
        error = EPROTO; goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "sysent_classification chroot_narg=%d same_slot0=%d same_slot8=%d same_slot11=%d same_fchdir=%d same_seteuid=%d",
                  entries[6].arguments, entries[6].call == entries[0].call,
                  entries[6].call == entries[1].call, entries[6].call == entries[2].call,
                  entries[6].call == entries[3].call, entries[6].call == entries[7].call);
    stage = "complete";
done:
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "probe_result build=%s stage=%s error=%d", LAPY_PROBE_ID, stage, error);
    ps5log_close(error ? "probe-failed" : "probe-complete");
    return error ? 1 : 0;
}
