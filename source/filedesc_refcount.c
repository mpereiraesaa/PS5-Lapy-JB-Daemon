#include "filedesc_refcount.h"
#include <errno.h>
#include <string.h>

int lapy_read_filedesc_refcount(const uint8_t *snapshot, size_t length,
                                unsigned offset, unsigned width,
                                uint32_t *value)
{
    if (!snapshot || !value || (width != 2 && width != 4) ||
        offset % width || offset > length || width > length - offset)
        return EINVAL;
    *value = 0;
    memcpy(value, snapshot + offset, width);
    return 0;
}

int lapy_calibrate_filedesc_refcount(const uint8_t *before,
                                     const uint8_t *shared,
                                     const uint8_t *separated,
                                     size_t length, unsigned *offset,
                                     unsigned *width)
{
    if (!before || !shared || !separated || !offset || !width ||
        length < 4 || length > 4096) return EINVAL;
    *offset = *width = 0;
    unsigned found = 0;
    for (unsigned at = 0; at + 2 <= length; at += 2) {
        unsigned selected = 0;
        for (unsigned bytes = 4; bytes >= 2; bytes -= 2) {
            uint32_t a = 0, b = 0, c = 0;
            if (at % bytes || at + bytes > length) continue;
            memcpy(&a, before + at, bytes);
            memcpy(&b, shared + at, bytes);
            memcpy(&c, separated + at, bytes);
            if (a == 1 && b == 2 && c == 1) {
                selected = bytes;
                break;
            }
        }
        if (selected) {
            ++found;
            *offset = at;
            *width = selected;
        }
    }
    if (found != 1) {
        *offset = *width = 0;
        return EPROTO;
    }
    return 0;
}
