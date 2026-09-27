#include "sony_scope.h"
#include <errno.h>
#include <string.h>

static int valid(const struct lapy_sony_ops *o)
{
    return o && o->identity && o->clone_current && o->read && o->write;
}

static int verify(const struct lapy_sony_scope *s, const struct lapy_sony_ops *o,
                  const struct lapy_sony_fields *expected)
{
    struct lapy_sony_fields actual;
    if (o->identity(o->context) != s->identity) return ESTALE;
    int error = o->read(o->context, s->identity, &actual);
    if (error) return error;
    return actual.authority == expected->authority &&
           !memcmp(actual.caps, expected->caps, sizeof(actual.caps)) ? 0 : EIO;
}

int lapy_sony_scope_begin(struct lapy_sony_scope *s, const struct lapy_sony_ops *o,
                         const struct lapy_sony_fields *desired)
{
    if (!s || !valid(o) || !desired) return EINVAL;
    if (s->active) return EBUSY;
    uintptr_t before = o->identity(o->context);
    if (!before) return ESRCH;
    int error = o->clone_current(o->context);
    if (error) return error;
    s->identity = o->identity(o->context);
    if (!s->identity) return ESRCH;
    if (s->identity == before) return ENOTSUP;
    error = o->read(o->context, s->identity, &s->original);
    if (error) return error;
    if (o->identity(o->context) != s->identity) return ESTALE;
    s->active = 1; /* Before the first possibly partial write. */
    error = o->write(o->context, s->identity, desired);
    return error ? error : verify(s, o, desired);
}

int lapy_sony_scope_end(struct lapy_sony_scope *s, const struct lapy_sony_ops *o)
{
    if (!s || !valid(o)) return EINVAL;
    if (!s->active) return 0;
    if (o->identity(o->context) != s->identity) return ESTALE;
    int error = o->write(o->context, s->identity, &s->original);
    if (!error) error = verify(s, o, &s->original);
    if (!error) s->active = 0;
    return error;
}
