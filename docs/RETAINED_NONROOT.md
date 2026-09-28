# Distinct old-root release under a retained stop

The two-root probe in PR #33 starts with a target whose old root is already the
system root. This FW 12.02 variant tests the missing **distinct old vnode**
case. It pins `/data` with a native descriptor, obtains its vnode identity by
native `chdir`, then restores the parent cwd to the system root. Its disposable
two-thread target natively changes cwd to `/data`. After the host debugger
stops both target threads, the probe stops a private single-thread donor and
uses three move-only transfers to put the target's owned `/data` cwd reference
in `fd_rdir`, while putting its old system-root reference in `fd_cdir`. No
reference is created or destroyed by these moves. The original non-system root
is therefore owned by the target before the actual two-root transaction.

A second donor provides another natively acquired system-root reference. The
same `lapy_replace_two_roots` transaction now moves the target's old `/data`
root into the first donor's vacant jail receiver, moves donor root references
into both target root/jail slots, and lets each donor exit through native
filedesc cleanup. The first donor's exit must release the old `/data` vnode
reference. The target then resumes and exits. The probe never changes vnode
counters or a homebrew title credential.

Expected system-root hold/use deltas relative to the pinned baseline are
`0, +1, +3, +3, +5, +5, +4, +3, 0` at `baseline`, `target_ready`,
`first_ready`, `nonroot_prepositioned`, `donors_ready`, `transfer_committed`,
`first_reaped`, `second_reaped`, `target_reaped`. Expected `/data` deltas are
`0, +1, +1, +1, +1, +1, 0, 0, 0`. Both final vnode samples must return to
baseline. The analyzer rejects a missing `/data` decrement at `first_reaped`
even when unrelated root-vnode activity affects an intermediate root sample.

Build with the installed SDK and logging client:

```sh
python3 tools/build_probe.py --probe retained-nonroot \
  --sdk /path/to/ps5-payload-sdk/install \
  --logging-client ../logging_server/client
```

Prepared build ID: `e947df36b9047ac0e1dafc2653c132a288ace55334c71c29580184cec6ad565d`;
ELF SHA-256: `c1c5bde0f1d7e388c51520f4e223f12996aed274be3e6c405d5483874abf800b`.
Recheck these in the generated manifest and ELF before running. The build
is offline-only so far; no console outcome is claimed.

At the next attended console session, start the lab `ps5log/1` receiver,
read the shared mailbox, take the `console:PS5` lease on an idle console, and
run one bounded cycle:

```sh
python3 tools/run_retained_nonroot.py --host "$PS5_HOST" \
  --ps5debug-python /path/to/rehd_mods
python3 tools/analyze_retained_nonroot.py STREAM.log SERVER.json \
  build/retained_nonroot-probe/manifest.json \
  build/retained_nonroot-probe/lapy_retained_nonroot_probe.elf
```

The coordinator verifies the ELF, selects a fresh identity-matched stream,
stops the disposable target with ps5debug-NG, waits for `transfer_committed`,
resumes it and requires three children reaped with clean `BYE`. The analyzer
requires exact artifact and stream identities, native `/data` reference
release and final balance. If the probe reports `probe_held`, all owners must
remain held for attended repair. Do not resume the target or kill the
coordinator in that state.

A pass would support the full **reference** path for a stopped disposable
process with an old root distinct from the system root. It would not validate
real-title PID retention, target credential cloning, all-thread behavior in
games, or repeat-safe production elevation. Those still need integration and
lifecycle testing.
