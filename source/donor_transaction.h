#ifndef LAPY_DONOR_TRANSACTION_H
#define LAPY_DONOR_TRANSACTION_H

#include <stdint.h>

/* These functions never create or release a vnode reference. Every non-null
 * input slot must already own one; the caller must keep all owners blocked
 * until COMPLETE or ROLLED_BACK. HELD means it must keep them blocked and
 * obtain an independent repair path before any owner can exit or resume. */
struct lapy_slot_io {
    int (*read)(void *context, intptr_t slot, intptr_t *value);
    int (*write)(void *context, intptr_t slot, intptr_t value);
    void *context;
};

enum lapy_move_result {
    LAPY_MOVE_UNCHANGED = 0,
    LAPY_MOVE_COMMITTED = 1,
    LAPY_MOVE_HELD = 2,
};

enum lapy_replace_result {
    LAPY_REPLACE_UNCHANGED = 0,
    LAPY_REPLACE_COMPLETE = 1,
    LAPY_REPLACE_ROLLED_BACK = 2,
    LAPY_REPLACE_HELD = 3,
};

enum lapy_move_result lapy_move_owned_ref(const struct lapy_slot_io *io,
                                           intptr_t source_slot,
                                           intptr_t empty_dest_slot,
                                           intptr_t expected_value);

/* Move the old target reference into a null receiver, then a native donor
 * root reference into the now-null target. The receiver's owner may exit to
 * release the old reference only after COMPLETE. A null old root needs no
 * receiver transfer. */
enum lapy_replace_result lapy_replace_owned_ref(
    const struct lapy_slot_io *io, intptr_t source_root_slot,
    intptr_t target_slot, intptr_t receiver_slot,
    intptr_t system_root, intptr_t expected_old);

#endif
