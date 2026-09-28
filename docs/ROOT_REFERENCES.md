# Direct root reference transaction

`source/root_references.c` implements ownership accounting for replacing the
root and jail directory slots with the system root. It does not use chroot.
It is **not yet connected to a PS5 native adapter or to the daemon**. The default
build remains unavailable; this component must not be presented as a fixed ELF.

The adapter contract in `root_references.h` requires native execution, a retained
live target, an exclusively owned filedesc, native synchronization and a pinned
destination vnode. Ordinary remote kernel memory writes cannot satisfy its
infallible publication contract. Native retain/release functions and their lock
ordering on firmware 12.02 remain unverified.

For each changed slot the transaction acquires one destination reference before
publication. Failure during acquisition releases all references acquired so far,
after unlocking, leaving both original slots intact. Successful publication
transfers those references to the slots; the old references are released after
unlocking because vnode release may sleep. Two slots pointing to the same vnode
still own two references. A null original jail owns none.

Repeated calls on already elevated slots do not acquire or release references.
This does **not** repair a process previously elevated by the legacy daemon:
pointer equality cannot reveal which references were omitted in the past.
Native validation must start from a clean boot without legacy elevation.

`make check` exercises an ownership model with all root/jail alias combinations,
null jail, acquisition rollback, missing adapter, invalid snapshots, 1000 repeated
no-op calls per combination, and 1000 elevation/copied-filedesc-fork/exit cycles.
These are host model tests, not console fork/LoadExec tests, native lock tests,
or evidence that vnode layouts match FreeBSD. No offsets are inferred or used.

Remaining delivery requirements: implement and verify the native adapter,
integrate error reporting and target lifetime handling in Lapy, preserve process
elevation, and measure direct /data operations and repeated native lifecycle
behavior. Credential isolation is a separate requirement. The reported crashes
remain consistent with reference imbalance but their exact cause is unproven.
