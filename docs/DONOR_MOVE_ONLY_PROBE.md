# Move-only donor transfer on disposable PS5 filedescs

Build the FW 12.02 probe with the installed SDK:

```sh
python3 tools/build_probe.py --sdk "$PS5_PAYLOAD_SDK" \
  --logging-client ../logging_server/client --probe move-only
```

The prepared artifact is `build/move_only-probe/lapy_move_only_probe.elf`,
build ID `5a477bd15d273839e0ed2fa1669cb162fabb2174510292ceba09fe4ff45a873e`,
SHA256 `a06655651ca06b90991dfcc0529926acb8457aa0847bc7a8dc9129353b9c875e`.
Run it once through elfldr under the console lease and retain its private
`ps5log/1` stream. It runs only on FW 12.02 and refuses any other firmware.
Validate the run against its exact server and build manifests:

```sh
python3 tools/analyze_move_only.py RUN.log RUN.json \
  build/move_only-probe/manifest.json \
  build/move_only-probe/lapy_move_only_probe.elf
```

This probe applies the host-tested `donor_transaction.c` move-only sequence
to its own private filedesc. Four blocked `rfork(RFPROC | RFFDG)` children
supply or receive natively owned references. One child obtains `/data` as
its current directory using native `chdir`; the probe first replaces its own
system root with that `/data` reference and lets a receiver exit to release
the displaced system-root reference. It then restores the system root with
another donor, lets the final receiver exit to release `/data`, and checks
that the root vnode's two observed fields return to the initial values.
The `/data` fields must drop by exactly one relative to the sample after
the native `chdir` acquisition. The probe never writes vnode counters, never
targets a game or launcher, and does not elevate credentials.

Passing this once, then repeated artifact-bound cycles, would establish the
move-only ownership and native-release sequence in disposable processes on
12.02. It would not establish a safe active-target daemon: target thread
quiescence, process retention, private-filedesc ownership, credential
isolation and other firmware layouts remain separate gates.

The preceding artifact completed 35 consecutive, analyzer-accepted cycles
with root baseline `60/59`. Its 36th run began at `61/60`, lost an unrelated
root reference during the first donor acquisition, then ended at `60/59`.
The analyzer correctly rejected that non-attributable run; a subsequent
isolated run passed. The revised artifact samples the baseline twice and
requires the expected `+1` and `+7` root deltas before the first pointer
transfer, so an early interference stops the probe before modification.

The revised artifact passed one isolated run and then six consecutive
artifact-bound cycles at baseline `60/59`. A seventh cycle finished with
`hold=60, use=60` and was rejected. A separate read-only root observer then
sampled 120 times over 119 seconds, starting at `60/59` and logging no
changes. Thus the one-field discrepancy did not persist, but its cause is
unattributed; do not count the rejected cycle as a balanced transfer.
