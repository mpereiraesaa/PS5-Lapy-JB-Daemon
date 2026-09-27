#include "root_references.h"
#include <errno.h>

int lapy_replace_roots(const struct lapy_root_ops *ops, void *ctx,
                       unsigned *changed)
{
    if (changed)
        *changed = 0;
    if (!ops || !ops->enter || !ops->retain || !ops->publish ||
        !ops->leave || !ops->release)
        return ENOTSUP;

    struct lapy_root_snapshot before = {0};
    int error = ops->enter(ctx, &before);
    if (error)
        return error;
    if (!before.root || !before.system_root) {
        ops->leave(ctx);
        return EPROTO;
    }

    unsigned mask = 0;
    if (before.root != before.system_root)
        mask |= LAPY_ROOT_CHANGED;
    if (before.jail != before.system_root)
        mask |= LAPY_JAIL_CHANGED;
    unsigned acquired = 0;
    for (unsigned bit = LAPY_ROOT_CHANGED; bit <= LAPY_JAIL_CHANGED; bit <<= 1) {
        if (!(mask & bit))
            continue;
        error = ops->retain(ctx, before.system_root);
        if (error) {
            ops->leave(ctx);
            while (acquired) {
                ops->release(ctx, before.system_root);
                --acquired;
            }
            return error;
        }
        ++acquired;
    }

    if (mask)
        ops->publish(ctx, before.system_root, before.system_root);
    ops->leave(ctx);

    /* References formerly owned by the changed slots are now ours to drop.
     * Aliased slots still own two separate references. Never deduplicate. */
    if (mask & LAPY_ROOT_CHANGED)
        ops->release(ctx, before.root);
    if ((mask & LAPY_JAIL_CHANGED) && before.jail)
        ops->release(ctx, before.jail);
    if (changed)
        *changed = mask;
    return 0;
}
