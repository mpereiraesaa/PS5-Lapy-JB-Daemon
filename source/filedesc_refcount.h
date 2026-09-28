#ifndef LAPY_FILEDESC_REFCOUNT_H
#define LAPY_FILEDESC_REFCOUNT_H

#include <stddef.h>
#include <stdint.h>

/* Identify an owning filedesc reference counter only from a native 1 -> 2 -> 1
 * transition on the same filedesc. The caller must keep the old table alive
 * for all three snapshots. Returns EPROTO on zero or ambiguous candidates. */
int lapy_calibrate_filedesc_refcount(const uint8_t *before,
                                     const uint8_t *shared,
                                     const uint8_t *separated,
                                     size_t length, unsigned *offset,
                                     unsigned *width);

/* Read the calibrated field from another snapshot. The caller separately
 * verifies process identity, address stability and exclusive ownership. */
int lapy_read_filedesc_refcount(const uint8_t *snapshot, size_t length,
                                unsigned offset, unsigned width,
                                uint32_t *value);

#endif
