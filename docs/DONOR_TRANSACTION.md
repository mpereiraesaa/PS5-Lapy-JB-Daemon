# Move-only vnode reference transaction

`source/donor_transaction.c` is the host-tested pointer-transfer core for a
future stopped-target adapter. It does not call PS5 kernel APIs or allocate
references. A donor must acquire each system-root reference through native
`rfork(RFPROC | RFFDG)` before the transaction; the target and all donors must
remain stopped or blocked, with verified private filedescs, until the result
is resolved.

For one target `fd_rdir` or `fd_jdir`, the sequence is:

1. Move its old non-null reference to an empty `fd_jdir` of a receiver donor
   by clearing the target slot first, then filling the receiver.
2. Move a natively acquired system-root reference from a source donor's
   `fd_rdir` to the empty target slot, again clearing the source first.
3. After a complete readback, let the receiver exit so the kernel releases
   the old root through `fdescfree`. The target retains the new reference,
   which its own exit or exec will release normally.

If the second move is proved unchanged, the engine moves the old reference
back and reports `ROLLED_BACK`. If a write or readback leaves ownership
ambiguous, it reports `HELD`: the adapter must neither release a donor nor
resume the target until an independent repair establishes every slot. This
is not an automatic success path. Clearing before filling can transiently
leave a reference without a slot, but never publishes two slots against one
reference. A daemon crash in that interval can leak a reference or leave the
target root null; it cannot by this sequence alone cause a double `vrele`.

The host test covers distinct, null and aliased old roots, errors before and
after kernel writes, rollback, and a lost readback. It checks the central
invariant after every simulated store: the number of non-null owning slots
for each vnode never exceeds the number of native references supplied. This
is a necessary part of the corrected daemon, not sufficient evidence to run
it against a live title. The target stop/retention, private-filedesc and
per-firmware offset gates still require PS5 validation.
