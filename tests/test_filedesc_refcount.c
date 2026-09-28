#include "filedesc_refcount.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void set32(uint8_t *bytes, unsigned offset, uint32_t value)
{
    memcpy(bytes + offset, &value, sizeof(value));
}

static void set16(uint8_t *bytes, unsigned offset, uint16_t value)
{
    memcpy(bytes + offset, &value, sizeof(value));
}

int main(void)
{
    uint8_t a[128] = {0}, b[128] = {0}, c[128] = {0};
    unsigned offset = 99, width = 99;
    uint32_t value = 0;
    set32(a, 0x34, 1); set32(b, 0x34, 2); set32(c, 0x34, 1);
    assert(!lapy_calibrate_filedesc_refcount(a, b, c, sizeof(a),
                                             &offset, &width));
    assert(offset == 0x34 && width == 4);
    assert(!lapy_read_filedesc_refcount(b, sizeof(b), offset, width, &value));
    assert(value == 2);
    set32(c, 0x34, 2);
    assert(lapy_calibrate_filedesc_refcount(a, b, c, sizeof(a),
                                            &offset, &width) == EPROTO);
    set32(c, 0x34, 1);
    set16(a, 0x48, 1); set16(b, 0x48, 2); set16(c, 0x48, 1);
    assert(lapy_calibrate_filedesc_refcount(a, b, c, sizeof(a),
                                            &offset, &width) == EPROTO);
    set16(a, 0x48, 0); set16(b, 0x48, 0); set16(c, 0x48, 0);
    assert(lapy_read_filedesc_refcount(a, sizeof(a), 127, 4, &value) == EINVAL);
    assert(lapy_read_filedesc_refcount(a, sizeof(a), 0x35, 2, &value) == EINVAL);
    puts("filedesc refcount calibration: ok");
    return 0;
}
