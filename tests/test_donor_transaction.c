#include "donor_transaction.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROOT 0x1000
#define OLD  0x2000

struct model {
    intptr_t slot[7];
    unsigned root_refs, old_refs;
    unsigned writes, reads;
    unsigned fail_write_at, fail_read_at;
    int fail_after_write;
    int duplicate_seen;
};

static void verify_no_duplicate(struct model *m)
{
    unsigned root = 0, old = 0;
    for (unsigned i = 1; i <= 6; ++i) {
        root += m->slot[i] == ROOT;
        old += m->slot[i] == OLD;
    }
    if (root > m->root_refs || old > m->old_refs)
        m->duplicate_seen = 1;
}

static int read_slot(void *context, intptr_t address, intptr_t *value)
{
    struct model *m = context;
    if (address < 1 || address > 6) return -1;
    if (++m->reads == m->fail_read_at) return -1;
    *value = m->slot[address];
    return 0;
}

static int write_slot(void *context, intptr_t address, intptr_t value)
{
    struct model *m = context;
    if (address < 1 || address > 6) return -1;
    ++m->writes;
    if (m->writes == m->fail_write_at && !m->fail_after_write)
        return -1;
    m->slot[address] = value;
    verify_no_duplicate(m);
    return m->writes == m->fail_write_at ? -1 : 0;
}

static struct lapy_slot_io io(struct model *m)
{
    struct lapy_slot_io result = {read_slot, write_slot, m};
    return result;
}

static struct model start(intptr_t old)
{
    struct model m;
    memset(&m, 0, sizeof(m));
    m.slot[1] = ROOT;
    m.slot[2] = old;
    m.root_refs = old == ROOT ? 2 : 1;
    m.old_refs = old == OLD ? 1 : 0;
    verify_no_duplicate(&m);
    return m;
}

static void success_cases(void)
{
    const intptr_t olds[] = {OLD, 0, ROOT};
    for (unsigned i = 0; i < sizeof(olds) / sizeof(olds[0]); ++i) {
        struct model m = start(olds[i]);
        struct lapy_slot_io operations = io(&m);
        assert(lapy_replace_owned_ref(&operations, 1, 2, 3,
                                      ROOT, olds[i]) == LAPY_REPLACE_COMPLETE);
        assert(m.slot[1] == 0 && m.slot[2] == ROOT &&
               m.slot[3] == olds[i]);
        assert(!m.duplicate_seen);
    }
}

static void fault_cases(void)
{
    /* No mutation on the initial evacuation failure. */
    struct model m = start(OLD);
    m.fail_write_at = 1;
    struct lapy_slot_io operations = io(&m);
    assert(lapy_replace_owned_ref(&operations, 1, 2, 3,
                                  ROOT, OLD) == LAPY_REPLACE_UNCHANGED);
    assert(m.slot[1] == ROOT && m.slot[2] == OLD && m.slot[3] == 0);
    assert(!m.duplicate_seen);

    /* An error returned after an actual write is resolved by readback. */
    m = start(OLD); m.fail_write_at = 2; m.fail_after_write = 1;
    operations = io(&m);
    assert(lapy_replace_owned_ref(&operations, 1, 2, 3,
                                  ROOT, OLD) == LAPY_REPLACE_COMPLETE);
    assert(m.slot[1] == 0 && m.slot[2] == ROOT && m.slot[3] == OLD);
    assert(!m.duplicate_seen);

    /* Destination install fails; source restoration and old-root rollback
     * both complete without ever duplicating a reference. */
    m = start(OLD); m.fail_write_at = 4;
    operations = io(&m);
    assert(lapy_replace_owned_ref(&operations, 1, 2, 3,
                                  ROOT, OLD) == LAPY_REPLACE_ROLLED_BACK);
    assert(m.slot[1] == ROOT && m.slot[2] == OLD && m.slot[3] == 0);
    assert(!m.duplicate_seen);

    m = start(OLD); m.fail_write_at = 4; m.fail_after_write = 1;
    operations = io(&m);
    assert(lapy_replace_owned_ref(&operations, 1, 2, 3,
                                  ROOT, OLD) == LAPY_REPLACE_COMPLETE);
    assert(m.slot[1] == 0 && m.slot[2] == ROOT && m.slot[3] == OLD);
    assert(!m.duplicate_seen);

    /* A lost readback after source clearance is unresolved. The caller
     * must hold both owners; no duplicated reference has been published. */
    m = start(OLD); m.fail_read_at = 6;
    operations = io(&m);
    assert(lapy_replace_owned_ref(&operations, 1, 2, 3,
                                  ROOT, OLD) == LAPY_REPLACE_HELD);
    assert(m.slot[1] == ROOT && m.slot[2] == 0 && m.slot[3] == 0);
    assert(!m.duplicate_seen);
}

static struct model start_two(intptr_t old_root, intptr_t old_jail)
{
    struct model m;
    memset(&m, 0, sizeof(m));
    m.slot[1] = ROOT; m.slot[2] = ROOT;
    m.slot[3] = old_root; m.slot[4] = old_jail;
    m.root_refs = 2 + (old_root == ROOT) + (old_jail == ROOT);
    m.old_refs = (old_root == OLD) + (old_jail == OLD);
    verify_no_duplicate(&m);
    return m;
}

static enum lapy_replace_result run_two(struct model *m,
                                         intptr_t old_root, intptr_t old_jail)
{
    struct lapy_slot_io operations = io(m);
    return lapy_replace_two_roots(&operations, 1, 2, 3, 4, 5, 6,
                                  ROOT, old_root, old_jail);
}

static void two_root_cases(void)
{
    const intptr_t olds[] = {0, OLD, ROOT};
    for (unsigned a = 0; a < 3; ++a)
        for (unsigned b = 0; b < 3; ++b) {
            struct model m = start_two(olds[a], olds[b]);
            assert(run_two(&m, olds[a], olds[b]) == LAPY_REPLACE_COMPLETE);
            assert(m.slot[1] == 0 && m.slot[2] == 0);
            assert(m.slot[3] == ROOT && m.slot[4] == ROOT);
            assert(m.slot[5] == olds[a] && m.slot[6] == olds[b]);
            assert(!m.duplicate_seen);
        }

    /* Inject a failure at every relevant read/write position, including an
     * error returned after a write that actually reached the model. */
    for (unsigned after = 0; after < 2; ++after)
        for (unsigned index = 1; index <= 42; ++index) {
            struct model m = start_two(OLD, 0);
            m.fail_after_write = after;
            if (index <= 18) m.fail_write_at = index;
            else m.fail_read_at = index - 18;
            enum lapy_replace_result result = run_two(&m, OLD, 0);
            assert(!m.duplicate_seen);
            if (result == LAPY_REPLACE_COMPLETE) {
                assert(m.slot[1] == 0 && m.slot[2] == 0);
                assert(m.slot[3] == ROOT && m.slot[4] == ROOT);
                assert(m.slot[5] == OLD && m.slot[6] == 0);
            } else if (result == LAPY_REPLACE_UNCHANGED ||
                       result == LAPY_REPLACE_ROLLED_BACK) {
                assert(m.slot[1] == ROOT && m.slot[2] == ROOT);
                assert(m.slot[3] == OLD && m.slot[4] == 0);
                assert(m.slot[5] == 0 && m.slot[6] == 0);
            }
        }

    struct model m = start_two(OLD, 0);
    struct lapy_slot_io operations = io(&m);
    assert(lapy_replace_two_roots(&operations, 1, 1, 3, 4, 5, 6,
                                  ROOT, OLD, 0) == LAPY_REPLACE_UNCHANGED);
    assert(!m.writes);
}

int main(void)
{
    success_cases();
    fault_cases();
    two_root_cases();
    puts("move-only donor transaction: two roots, ownership, rollback and faults passed");
    return 0;
}
