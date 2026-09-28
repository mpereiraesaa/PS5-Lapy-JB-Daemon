# Two-root reference transaction: next console probe

The old daemon overwrites a target's `fd_rdir` and `fd_jdir` with the system
root without acquiring references. The new `lapy_replace_two_roots` transaction
uses two separate system-root references acquired by native `rfork(RFPROC|RFFDG)`
filedesc copying. It first moves each displaced target reference into a vacant
receiver slot, then moves a donor reference into each target slot. Receiver
filedescs release their displaced references on native process exit. It never
writes vnode counters. Before mutation, it checks all six distinct slots; on
an indeterminate write or readback it returns `HELD`, which requires keeping
all owners blocked rather than allowing an ambiguous exit. Host fault tests
cover null, same-root and distinct old roots in either slot, plus read/write
faults and rollback.

`source/retained_two_root_probe.c` exercises the whole transaction on FW 12.02
using disposable processes, not a homebrew title. The target has two threads,
a private filedesc, an owned system `fd_rdir` and a null `fd_jdir`. A separate
SceShellCore debugger must stop both target threads. Two single-thread donors
each own a native system-root `fd_rdir` reference and have a null jail receiver
slot. The probe stops and verifies each donor before touching its filedesc.
The first donor receives the target's old root reference; the second supplies
the new jail reference. The target stays stopped during publication. After
commit, both donors exit natively, then the target resumes and exits. Root
vnode hold/use samples should follow `0, +2, +4, +6, +6, +4, +3, 0`
relative to baseline. The intermediate `+4/+3` samples may be affected by
unrelated VFS activity and are reported as interference; final baseline is
required.

Built offline with the installed SDK and logging client:

```sh
python3 tools/build_probe.py --probe retained-two-root \
  --sdk /path/to/ps5-payload-sdk/install \
  --logging-client ../logging_server/client
```

The prepared build ID is
`b10502a375aeefc64536ba81fd6bbde4e854de39cb3a7a0a545da6a6664f7c17`;
ELF SHA-256 is
`6ec9134f2089ff8cbbea2634390bf086cc84ec481b5d1e0b5ff63fb089f6ce2f`.
Recheck these against `build/retained_two_root-probe/manifest.json` before
running; rebuilding changes the identity.

For the next attended console session, start the lab `ps5log/1` receiver,
read the coordination mailbox, acquire `console:PS5` via `ps5-console run` on
an idle console, and invoke:

```sh
python3 tools/run_retained_two_root.py --host "$PS5_HOST" \
  --ps5debug-python /path/to/rehd_mods
```

The coordinator checks the ELF against its manifest, sends it through elfldr,
selects a fresh identity-matched log stream, attaches to the disposable child,
sends debugger STOP, waits for `transfer_committed`, sends RESUME and detaches.
It requires a complete `BYE` and three reaped children. On `probe_held` it
intentionally keeps the debugger and console lease alive for manual repair;
do not kill the coordinator or resume the target in that state.

Validate the matching private stream, server manifest and exact ELF after the
run:

```sh
python3 tools/analyze_retained_two_root.py STREAM.log SERVER.json \
  build/retained_two_root-probe/manifest.json \
  build/retained_two_root-probe/lapy_retained_two_root_probe.elf
```

The analyzer requires the reference sequence, complete native exits and the
final root-vnode hold/use values to equal the initial values. It rejects an
incomplete stream or mismatched artifact identity.

A passing run proves the two-root lifetime sequence only for these disposable
FW 12.02 processes. It does not clone target credentials, retain an unrelated
title PID through process exit/exec, validate a non-system displaced old root
in the same stopped cross-process transaction, or authorize deployment as the
production Lapy daemon. Those remain explicit gates before unrestricted
repeated homebrew elevation.
