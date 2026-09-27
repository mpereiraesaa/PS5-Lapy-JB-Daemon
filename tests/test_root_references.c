#include "root_references.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Integer vnode identities model ownership, not any firmware layout. */
struct model {
    struct lapy_root_snapshot dirs;
    int refs[4];
    int locked, enters, leaves, retains, publishes, releases;
    int enter_error, fail_retain;
};

static int enter(void *arg, struct lapy_root_snapshot *out)
{
    struct model *m = arg;
    assert(!m->locked);
    ++m->enters;
    if (m->enter_error)
        return m->enter_error;
    m->locked = 1;
    *out = m->dirs;
    return 0;
}

static int retain(void *arg, uintptr_t vnode)
{
    struct model *m = arg;
    assert(m->locked && vnode == 1 && m->refs[vnode] > 0);
    ++m->retains;
    if (m->retains == m->fail_retain)
        return EAGAIN;
    ++m->refs[vnode];
    return 0;
}

static void publish(void *arg, uintptr_t root, uintptr_t jail)
{
    struct model *m = arg;
    assert(m->locked && root == 1 && jail == 1);
    assert(m->refs[1] >= 3); /* Baseline pin plus both field references. */
    ++m->publishes;
    m->dirs.root = root;
    m->dirs.jail = jail;
}

static void leave(void *arg)
{
    struct model *m = arg;
    assert(m->locked);
    m->locked = 0;
    ++m->leaves;
}

static void release(void *arg, uintptr_t vnode)
{
    struct model *m = arg;
    assert(!m->locked && vnode > 0 && vnode < 4);
    assert(m->refs[vnode] > 0);
    --m->refs[vnode];
    ++m->releases;
}

static const struct lapy_root_ops ops = {enter, retain, publish, leave, release};

static struct model init(uintptr_t root, uintptr_t jail)
{
    struct model m = {.dirs = {root, jail, 1}, .refs = {0, 1, 0, 0}};
    if (root) ++m.refs[root];
    if (jail) ++m.refs[jail];
    return m;
}

static void check_baseline(struct model *m)
{
    assert(!m->locked);
    assert(m->refs[1] == 1 && m->refs[2] == 0 && m->refs[3] == 0);
}

static void exit_process(struct model *m)
{
    release(m, m->dirs.root);
    if (m->dirs.jail) release(m, m->dirs.jail);
    m->dirs.root = m->dirs.jail = 0;
}

static void success_cases(void)
{
    for (uintptr_t root = 1; root <= 3; ++root) {
        for (uintptr_t jail = 0; jail <= 3; ++jail) {
            struct model m = init(root, jail);
            unsigned wanted = (root != 1 ? LAPY_ROOT_CHANGED : 0) |
                              (jail != 1 ? LAPY_JAIL_CHANGED : 0);
            unsigned changed = 99;
            assert(lapy_replace_roots(&ops, &m, &changed) == 0);
            assert(changed == wanted);
            assert(m.refs[1] == 3 && !m.refs[2] && !m.refs[3]);
            int retains = m.retains, releases = m.releases, pubs = m.publishes;
            for (int i = 0; i < 1000; ++i) {
                changed = 99;
                assert(lapy_replace_roots(&ops, &m, &changed) == 0);
                assert(changed == 0);
            }
            assert(m.retains == retains && m.releases == releases &&
                   m.publishes == pubs && !m.locked);
            exit_process(&m);
            check_baseline(&m);
        }
    }
}

static void failure_cases(void)
{
    for (int fail = 1; fail <= 2; ++fail) {
        struct model m = init(2, 2), before = m;
        m.fail_retain = fail;
        unsigned changed = 99;
        assert(lapy_replace_roots(&ops, &m, &changed) == EAGAIN);
        assert(changed == 0 && !m.locked && m.leaves == 1 && !m.publishes);
        assert(!memcmp(m.refs, before.refs, sizeof(m.refs)));
        assert(!memcmp(&m.dirs, &before.dirs, sizeof(m.dirs)));
        exit_process(&m);
        check_baseline(&m);
    }
    struct model m = init(2, 3);
    m.enter_error = ESRCH;
    assert(lapy_replace_roots(&ops, &m, NULL) == ESRCH);
    assert(!m.locked && !m.leaves && !m.retains && !m.publishes);
    m.enter_error = 0;
    m.dirs.system_root = 0;
    assert(lapy_replace_roots(&ops, &m, NULL) == EPROTO);
    assert(m.leaves == 1 && !m.retains && !m.publishes);
    m.dirs.system_root = 1;
    m.dirs.root = 0;
    assert(lapy_replace_roots(&ops, &m, NULL) == EPROTO);
    assert(m.leaves == 2 && !m.retains && !m.publishes);
    struct lapy_root_ops missing = ops;
    missing.publish = NULL;
    unsigned changed = 99;
    int enters = m.enters;
    assert(lapy_replace_roots(&missing, &m, &changed) == ENOTSUP);
    assert(!changed && m.enters == enters);
    assert(lapy_replace_roots(NULL, &m, NULL) == ENOTSUP);
}

static void lifecycle_cases(void)
{
    for (int cycle = 0; cycle < 1000; ++cycle) {
        struct model m = init(2, 3);
        assert(lapy_replace_roots(&ops, &m, NULL) == 0);
        /* Model native fork with copied filedesc: one reference per slot. */
        uintptr_t child_root = m.dirs.root, child_jail = m.dirs.jail;
        ++m.refs[child_root];
        ++m.refs[child_jail];
        exit_process(&m);
        release(&m, child_root);
        release(&m, child_jail);
        check_baseline(&m);
    }
}

int main(void)
{
    success_cases();
    failure_cases();
    lifecycle_cases();
    puts("root ownership model: aliasing, rollback, idempotence and lifecycle passed");
    return 0;
}
