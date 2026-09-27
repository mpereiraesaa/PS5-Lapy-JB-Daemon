/* Read-only kldsym availability probe. No returned kernel address is called,
 * dereferenced or sent to the logger. This tests symbol lookup, not ABI safety. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/syscall.h>

#if !defined(__x86_64__) || SYS_kldsym != 337
#error "Requires the reviewed PS5 x86-64 kldsym syscall ABI"
#endif

static int checked_kldsym(struct kld_sym_lookup *lookup)
{
    long value;
    unsigned char failed;
    __asm__ volatile("syscall\n\tsetc %1"
                     : "=a"(value), "=qm"(failed)
                     : "a"((long)SYS_kldsym), "D"(0L),
                       "S"((long)KLDSYM_LOOKUP), "d"(lookup)
                     : "rcx", "r11", "memory", "cc");
    return failed ? (value > 0 && value <= 4095 ? (int)value : EIO)
                  : (value == 0 ? 0 : EPROTO);
}

int main(void)
{
    static const char *const symbols[] = {
        "copyin", "copyout", "vref", "vrele", "fdunshare",
        "fdcopy", "sx_xlock", "sx_xunlock", "proc_rele"
    };
    unsigned found = 0;
    if (ps5log_init_default("LAPYSYM", "lapy-kernel-symbol-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x count=%u mode=lookup-only",
                  LAPY_PROBE_ID, kernel_get_fw_version(),
                  (unsigned)(sizeof(symbols) / sizeof(symbols[0])));
    for (unsigned i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
        struct kld_sym_lookup lookup = {
            .version = sizeof(lookup), .symname = (char *)symbols[i]
        };
        int error = checked_kldsym(&lookup);
        uintptr_t address = (uintptr_t)lookup.symvalue;
        int canonical = address && (address >> 48) == UINT64_C(0xffff);
        if (!error && canonical) ++found;
        /* Never print a kernel pointer or address delta. For a usable symbol,
         * the future native adapter must resolve and validate it itself. */
        ps5log_printf(PS5LOG_MARK,
                      "symbol_result build=%s name=%s error=%d canonical=%d size=%zu",
                      LAPY_PROBE_ID, symbols[i], error, canonical,
                      error ? 0 : lookup.symsize);
    }
    ps5log_printf(PS5LOG_MARK,
                  "probe_result build=%s found=%u total=%u lookup_only=1",
                  LAPY_PROBE_ID, found,
                  (unsigned)(sizeof(symbols) / sizeof(symbols[0])));
    ps5log_close("probe-complete");
    return 0;
}
