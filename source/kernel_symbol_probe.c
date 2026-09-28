/* Read-only kldsym availability probe. No returned kernel address is called,
 * dereferenced or sent to the logger. This tests symbol lookup, not ABI safety. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "probe_identity.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <string.h>
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

static unsigned lookup_one(const char *symbol)
{
    struct kld_sym_lookup lookup = {
        .version = sizeof(lookup), .symname = (char *)symbol
    };
    int error = checked_kldsym(&lookup);
    uintptr_t address = (uintptr_t)lookup.symvalue;
    int canonical = address && (address >> 48) == UINT64_C(0xffff);
    ps5log_printf(PS5LOG_MARK,
                  "symbol_result build=%s name=%s name_len=%zu error=%d canonical=%d size=%zu",
                  LAPY_PROBE_ID, symbol, strlen(symbol), error, canonical,
                  error ? 0 : lookup.symsize);
    return !error && canonical;
}

int main(void)
{
    unsigned found = 0;
    if (ps5log_init_default("LAPYSYM", "lapy-kernel-symbol-probe"))
        return 2;
    ps5log_printf(PS5LOG_MARK,
                  "probe_start build=%s firmware=%08x count=%u mode=lookup-only",
                  LAPY_PROBE_ID, kernel_get_fw_version(), 9u);
    /* Pass literals directly: the PS5 ELF loader may not relocate a static
     * array of string pointers. A null name invalidates the lookup result. */
    found += lookup_one("copyin");
    found += lookup_one("copyout");
    found += lookup_one("vref");
    found += lookup_one("vrele");
    found += lookup_one("fdunshare");
    found += lookup_one("fdcopy");
    found += lookup_one("sx_xlock");
    found += lookup_one("sx_xunlock");
    found += lookup_one("proc_rele");
    ps5log_printf(PS5LOG_MARK,
                  "probe_result build=%s found=%u total=%u lookup_only=1",
                  LAPY_PROBE_ID, found, 9u);
    ps5log_close("probe-complete");
    return 0;
}
