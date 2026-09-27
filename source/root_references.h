#ifndef LAPY_ROOT_REFERENCES_H
#define LAPY_ROOT_REFERENCES_H

#include <stdint.h>

struct lapy_root_snapshot {
    uintptr_t root;
    uintptr_t jail; /* A null jail owns no reference. */
    uintptr_t system_root;
};

/* Native kernel adapter contract, NOT a kernel_copyin/copyout adapter.
 *
 * enter: retain the intended live process, establish an exclusively owned
 * filedesc for it, pin system_root, and hold the native filedesc write lock.
 * Return a snapshot taken under that lock. On failure leave no resources held.
 * The adapter must resolve lock ordering and filedesc unsharing itself.
 *
 * retain: acquire one real vnode use reference. An error acquires NOTHING.
 * Must be valid with the filedesc lock held (including vnode lock ordering).
 *
 * publish: install both pointers under the held lock. Infallible native
 * stores only: no remote writes, fallible transport, or partial publication.
 * This transfers one acquired reference to each changed field.
 *
 * leave: release the filedesc lock and enter's lifetime pins. Infallible.
 * release: native vnode release, after leave, and may sleep. Infallible.
 * Context must remain valid through the final release.
 *
 * These conditions require firmware-specific verification. A callback model
 * passing host tests does not establish that a PS5 adapter meets them.
 */
struct lapy_root_ops {
    int (*enter)(void *, struct lapy_root_snapshot *);
    int (*retain)(void *, uintptr_t);
    void (*publish)(void *, uintptr_t, uintptr_t);
    void (*leave)(void *);
    void (*release)(void *, uintptr_t);
};

enum { LAPY_ROOT_CHANGED = 1, LAPY_JAIL_CHANGED = 2 };

/* Returns positive errno. changed is optional, zero on any failure/no-op.
 * An already-elevated field gets no additional reference. Pointer equality
 * does not repair references missing from an earlier legacy elevation.
 */
int lapy_replace_roots(const struct lapy_root_ops *, void *, unsigned *changed);

#endif
