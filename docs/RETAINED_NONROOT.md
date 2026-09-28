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

The first FW 12.02 hardware attempt reached `target_ready` with two threads,
private filedesc and one native `/data` reference. Host ps5debug-NG rejected
`DEBUG_ATTACH` before stopping the child. The probe timed out at `target_stop`
with `moved=0`, emitted `BYE reason=probe-failed`, and cleaned up both payload
processes. It provides no evidence for or against the reference transaction.
The ps5debug server dials back to host port 755; that low-port proxy was not
active for this attempt.

For a separate disposable **reference-lifetime** test, build with
`--probe retained-nonroot --self-stop` and the same SDK/logging-client options.
The parent sends `SIGSTOP` to its own target after `target_ready`; it still
requires two identical stopped snapshots and a private filedesc before moving
any reference. `release_child` sends `SIGCONT` before native exit. This variant
does not test ps5debug attachment or retained identity of an unrelated title.
It has an isolated artifact directory, `build/retained_nonroot-probe/self-stop/`,
and a manifest field `self_stop=true`. Its prepared build ID is
`8e49c7d6c9349dc4dd3614714b8866cfeaa23fe12ed78d0f0c53aa3fef62679a`;
ELF SHA-256 is
`bb764c5d170091bd68d09c6e133bb210ddece49837eb77a42f8accc301bb326d`.
Under the console lease with the `ps5log/1` receiver active, run exactly one
cycle using:

```sh
python3 tools/run_retained_nonroot_self_stop.py --host "$PS5_HOST" \
  --runs ../logging_server/runs
```

The runner checks the ELF, build manifest, complete stream and native release
with the existing artifact-bound analyzer. If it reports `probe_held`, leave
the payload and its owners untouched for attended repair. A pass proves only
the disposable reference transaction and final balance on this firmware.

The first self-stop console cycle passed on FW 12.02. Its clean private stream
is `20260928T094836049Z_LAPYNROOT_lapy-retained-nonroot-old_0x235750bebf25`
(log SHA-256
`44982a9407ca87c117d840f8a20b20e609ec50d9a3acfa864634fb8b89e08de7`).
The artifact-bound analyzer reported `balanced=true` and
`intermediate_interference=false`; root hold/use began at 69/68, `/data` at
3/3, and both returned to those exact baselines after native donor and target
exit. The complete result includes all three reaped children and a clean BYE.
No payload process remained after the run. This is concrete FW 12.02 evidence
for reference ownership across the disposable transfer, not yet evidence for
a live title's credential propagation, PID retention or repeat-safe daemon.
