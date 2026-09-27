#include "sony_scope.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct model { uintptr_t id; struct lapy_sony_fields fields; int clone_error, no_clone;
               int read_error, partial_write, corrupt_write, writes; };
static uintptr_t identity(void *p) { return ((struct model *)p)->id; }
static int clone(void *p) {
    struct model *m = p;
    if (m->clone_error) return m->clone_error;
    if (!m->no_clone) ++m->id;
    return 0;
}
static int read_fields(void *p, uintptr_t id, struct lapy_sony_fields *f) {
    struct model *m = p; assert(id == m->id);
    if (m->read_error) return m->read_error;
    *f = m->fields; return 0;
}
static int write_fields(void *p, uintptr_t id, const struct lapy_sony_fields *f) {
    struct model *m = p; assert(id == m->id); ++m->writes;
    m->fields.authority = f->authority;
    if (m->partial_write) return EIO;
    memcpy(m->fields.caps, f->caps, sizeof(f->caps));
    if (m->corrupt_write) m->fields.caps[0] ^= 1;
    return 0;
}
int main(void) {
    struct lapy_sony_fields original = {0}, desired = {.authority = 7};
    memset(desired.caps, 0xff, sizeof(desired.caps));
    for (int failure = 0; failure < 7; ++failure) {
        struct model m = {.id = 1};
        struct lapy_sony_ops ops = {&m, identity, clone, read_fields, write_fields};
        struct lapy_sony_scope scope = {0};
        if (failure == 1) m.clone_error = EPERM;
        if (failure == 2) m.no_clone = 1;
        if (failure == 3) m.read_error = EFAULT;
        if (failure == 4) m.partial_write = 1;
        if (failure == 5) m.corrupt_write = 1;
        int error = lapy_sony_scope_begin(&scope, &ops, &desired);
        if (failure >= 1 && failure <= 5) assert(error);
        else assert(!error);
        if (failure >= 1 && failure <= 3) assert(!scope.active && m.writes == 0);
        else assert(scope.active);
        if (scope.active) assert(lapy_sony_scope_begin(&scope, &ops, &desired) == EBUSY);
        m.partial_write = 0; m.corrupt_write = 0; m.read_error = 0;
        if (failure == 6) {
            ++m.id;
            int count = m.writes;
            assert(lapy_sony_scope_end(&scope, &ops) == ESTALE && scope.active);
            assert(m.writes == count); /* Never write the stale pointer. */
            --m.id;
            m.partial_write = 1;
            assert(lapy_sony_scope_end(&scope, &ops) == EIO && scope.active);
            m.partial_write = 0;
        }
        assert(lapy_sony_scope_end(&scope, &ops) == 0 && !scope.active);
        assert(!memcmp(&m.fields, &original, sizeof(original)));
        int count = m.writes;
        assert(lapy_sony_scope_end(&scope, &ops) == 0 && m.writes == count);
    }
    puts("Sony scope: clone rejection, partial writes, readback, stale identity and restoration passed");
}
