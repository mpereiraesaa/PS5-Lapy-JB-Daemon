#ifndef LAPY_SONY_SCOPE_H
#define LAPY_SONY_SCOPE_H
#include <stdint.h>

struct lapy_sony_fields { uint64_t authority; unsigned char caps[16]; };
struct lapy_sony_ops {
    void *context;
    uintptr_t (*identity)(void *);
    int (*clone_current)(void *);
    int (*read)(void *, uintptr_t, struct lapy_sony_fields *);
    int (*write)(void *, uintptr_t, const struct lapy_sony_fields *);
};
struct lapy_sony_scope {
    uintptr_t identity;
    struct lapy_sony_fields original;
    int active;
};

/* Zero-initialize scope. Caller must exclude fork/exec, credential replacement
 * and changes by every thread for the entire scope. The callbacks operate on
 * that caller's current credential; no remote PID reuse is permitted.
 * Pointer replacement alone does NOT establish this exclusion.
 * Always call end, including after failed begin: a partial write can leave an
 * active scope. Failed end keeps active set and must be reported as unresolved.
 * Operations return positive errno. Neither function writes reference fields. */
int lapy_sony_scope_begin(struct lapy_sony_scope *, const struct lapy_sony_ops *,
                         const struct lapy_sony_fields *);
int lapy_sony_scope_end(struct lapy_sony_scope *, const struct lapy_sony_ops *);
#endif
