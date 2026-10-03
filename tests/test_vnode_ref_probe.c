#include "vnode_ref_probe.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    const struct lapy_vnode_ref_counts before = {73, 72};
    const struct lapy_vnode_ref_counts with_donor = {75, 74};
    const struct lapy_vnode_ref_counts released = {73, 72};
    const struct lapy_vnode_ref_counts hidden_by_release = {72, 71};
    const struct lapy_vnode_ref_counts wrong_hold = {75, 73};
    const struct lapy_vnode_ref_counts leaked = {74, 73};
    const struct lapy_vnode_ref_counts near_overflow = {UINT32_MAX, 12};

    assert(lapy_vnode_ref_probe_added_two(&before, &with_donor));
    assert(lapy_vnode_ref_probe_returned_to_baseline(&before, &released));

    /* Concurrent global vnode activity makes a sample inconclusive. */
    assert(!lapy_vnode_ref_probe_added_two(&before, &hidden_by_release));
    assert(!lapy_vnode_ref_probe_added_two(&before, &wrong_hold));
    assert(!lapy_vnode_ref_probe_returned_to_baseline(&before, &leaked));
    assert(!lapy_vnode_ref_probe_added_two(&near_overflow, &with_donor));
    assert(!lapy_vnode_ref_probe_added_two(NULL, &with_donor));
    assert(!lapy_vnode_ref_probe_returned_to_baseline(&before, NULL));

    puts("vnode reference probe: exact +2 and release baseline required");
    return 0;
}
