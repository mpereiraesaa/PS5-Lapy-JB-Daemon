# Retained cross-process reference transfer probe

This FW 12.02-only probe tests one missing link between the disposable
move-only transaction and a live title. It creates two private-filedesc child
processes. The first child has two threads and serves as the target; the second
owns a system-root `fd_rdir` reference acquired by native `rfork(RFPROC|RFFDG)`.
The parent reports `target_ready` through `ps5log/1` and waits until the
SceShellCore ps5debug-NG debugger stops the target. It requires two identical
thread-list snapshots with `p_suspcount == 2`, a stable process and filedesc
address, a private filedesc (`fd_refcnt == 1`), the expected root, and a null
jail slot. It then moves the donor's owned reference into the target's jail
slot with `lapy_move_owned_ref`, verifies the donor's source slot is null and
the target remains stopped, and lets both children exit through their native
cleanup paths after the host resumes the target.

The root-vnode read-only hold/use fields calibrated on this console normally
follow `0, +2, +4, +4, +3, 0` relative to the initial sample: target created,
donor created, reference moved, donor reaped, target reaped. The pre-transfer
samples must match exactly. The post-donor sample is recorded as interference
if other system activity changes it; the probe still lets the target exit and
requires the final value to return to baseline within one second. A missing
final balance fails the run.

Build with `tools/build_probe.py --probe retained-cross-process` using the
installed SDK and logging client. A host coordinator must parse the fresh
`target_ready` build ID and PID, attach using ps5debug-NG, send STOP, wait for
`transfer_committed`, send RESUME, detach, and preserve the complete stream and
ELF manifest. The probe's 12-second stop window and 30-second child alarm are
hard bounds, not a production lifetime policy. On an indeterminate pointer
transfer (`LAPY_MOVE_HELD`), the parent reports `probe_held` and retains both
owners indefinitely for manual repair; the coordinator must not resume the
target in that state.

This is a disposable reference-lifetime experiment. It does not clone or
elevate a title's credentials, handle a non-null old jail, prove target exit
retention, or grant `/data` to Prospero Win. Its layout checks are deliberately
restricted to FW 12.02; other firmware must be calibrated and gated separately.

## First owned 12.02 run

Build `14dd7e000376072930418f4b6403d58e4d452fc4e646feb90c004053d9ce5e81`
(ELF SHA256 `7701b16a840dc0b0d2efea3606a366ca31c2a27a5cbd486fd393da077da2bc17`)
completed with private stream SHA256
`acae4458c76d44bb989366f149b9c4c1a7435f632fc9fce5a4433b6fee8c5102`.
The target had a private filedesc and two threads; SceShellCore debugger STOP
yielded two suspended threads. The root reference moved from donor `fd_rdir`
to target `fd_jdir`, with the source null and target still stopped. After
RESUME/detach, both children exited and were reaped; the stream ended with
`BYE`. This first build did not sample root-vnode counters. The later build
adds the exact counter sequence above and requires a separate console run.

The first counter-checked run (build
`22cffd641419af994f637a0e7b73170b2cb20fe1d809f1ad819856e0d938cb40`,
ELF SHA256 `38fbbc63dc8e2441928624fc1a3961f1792fbe677556fedbffca8ea46c171eab`)
passed with private stream SHA256
`0ffa2ee8c404df9c23041fe17ed732218665d6b4b88bb183e6d4faf4a0edc603`.
Its hold/use sequence was `61/60, 63/62, 65/64, 65/64, 64/63, 61/60`.
Four more cycles passed with the same baseline. On the fifth, the donor-exit
sample rose to `66/65`, so the strict build stopped early; it did not record
a final sample. The immediately following independent run began and ended at
`61/60`, which rules out a persistent two-reference loss in that cycle but
does not identify the concurrent activity. The revised probe records the
intermediate anomaly and always checks final balance after target exit.
