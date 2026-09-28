# Live title stop observer

This FW 12.02 only, one-shot probe watches for a fresh Lapy request from
`PPSA99995` by default. Build with `--target-title PPSA99994` to observe the
isolated Hello World gate instead. The target title is part of the artifact
identity and appears in the `probe_start` telemetry. The probe waits for a
request for up to 60 seconds. It reads the requester's PID and validates its
kernel process identity, then sends `SIGSTOP`, counts all linked threads and
checks the observed suspension field against that count twice. It also checks
that the target `filedesc` is private (`fd_refcnt == 1`). It resumes the title
with `SIGCONT` and removes the request marker in every exit path after a
request is found, so the caller can continue. It never elevates or writes
kernel memory; `/data` access will still fail after its acknowledgement.

Build with `tools/build_probe.py --probe live-target-stop` and the installed
SDK and logging client. Run only while the actual target title is available,
under the lab's `console:PS5` lease, and keep the exact ELF identity alongside
the private `ps5log/1` stream. A clean result establishes only that this
particular title was held and resumed under the observed conditions. It does
not transfer vnode references or clone target credentials. Any failed signal,
unstable identity/list, missing request or shared `filedesc` is a failed gate;
there is no elevation fallback.

This is a diagnostic probe, not a production authorization path. A PID read
from the marker cannot be retained across a userland `kill(pid, SIGSTOP)`;
exit and PID reuse in that window remain possible. A production backend needs
a retained target identity or a cooperative target-side stop protocol before
using this operation. The first owned-console attempt did not reach this path:
launching `PPSA99995` returned `0x80940033`, no request appeared, and the probe
completed a clean 60-second timeout without signaling any process. It therefore
provided no evidence about whether an unrelated title could be stopped and
resumed by Lapy.

The isolated `PPSA99994` Hello World gate subsequently produced a fresh request.
On FW 12.02, build
`e698b895eb1bc6bf92c4654c238d94e73c9ce36a053856d015bf56c1a4192a44`
(ELF SHA-256
`8cfac3fdf48d5b43ca1bfb468f2d4cdc36cd2791ce64f5493bfae474a2014dd0`)
observed target PID 1141, one linked thread, one suspended thread, stable
identity across two stopped snapshots and `fd_refcnt == 1`. Both `SIGSTOP` and
`SIGCONT` succeeded; the probe acknowledged the marker and exited cleanly.
The title's separate `ps5log/1` stream reached `data_wait_timeout errno=2`,
as expected because this observer did not elevate it. Private evidence:
`20260928T090712986Z_LAPYTS_lapy-live-target-stop-probe_0x211530c98814` and
`20260928T090714565Z_PPSA99994_lapy-hello-elevation-gate_0x21158eb62c73`.
This single-thread observation does not establish all-thread quiescence for
other titles or solve the PID-retention race described above.

## Read-only pre-elevation state variant

Build `PPSA99994` with `python3 tools/build_probe.py --probe live-target-stop
--target-title PPSA99994 --observe-state --sdk <installed-sdk>
--logging-client ../logging_server/client`. This variant observes the stopped
target's root, jail, current directory, credential and prison fields in two
snapshots. It emits only boolean comparisons with the system root and expected
privileged values, never kernel pointers or credential values. The target is
resumed and acknowledged by the same path as the original stop probe. No
elevation or kernel write is performed.

The offline FW 12.02 artifact in `build/live_target_stop-probe/PPSA99994/state/`
has build ID `f67ac3d1565290fbe49f49408ba3068ff32fb4ee4f5af141393ba9ab5f1a855f`
and ELF SHA-256
`52ced259f11c95968d515a96759344069c5de3aa0103f1c7cb5bfae4ed54fb79`.
These identify this specific build, not a console validation. Launch the
observer through elfldr, launch the isolated Hello World title while it waits
for a fresh request, and collect the private `LAPYTS` `ps5log/1` stream and
its server manifest. Under the global `console:PS5` lease, close the title
after the observer acknowledges it. Analyze the exact artifacts with:

```sh
python3 tools/analyze_live_target_state.py \
  <LAPYTS.log> <LAPYTS.server.json> \
  build/live_target_stop-probe/PPSA99994/state/manifest.json \
  build/live_target_stop-probe/PPSA99994/state/lapy_live_target_stop_probe.elf
```

The analyzer requires a clean stream, exact ELF hash and build ID, a private
filedesc, stable stopped thread list, successful resume and all state fields.
It reports observed identity flags only. A positive result would establish the
pre-elevation state of this one title at that instant; it cannot prove vnode
reference ownership, all-thread behavior of other titles, or safety of a
subsequent root transfer. The legacy daemon's on-screen `unsandboxed`
notification confirms that it acknowledged a separate request and does not
validate this read-only variant or the reference-lifetime hypothesis.
