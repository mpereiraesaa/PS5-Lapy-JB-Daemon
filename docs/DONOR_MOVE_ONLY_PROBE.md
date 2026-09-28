# Move-only donor transfer on disposable PS5 filedescs

Build the FW 12.02 probe with the installed SDK:

```sh
python3 tools/build_probe.py --sdk "$PS5_PAYLOAD_SDK" \
  --logging-client ../logging_server/client --probe move-only
```

The prepared artifact is `build/move_only-probe/lapy_move_only_probe.elf`,
build ID `a54db5dc4a79591ada2f27d781c189f7f056ccdefde37369a35856c92fa48f3a`,
SHA256 `a0bbe941f571e61bc565c396a2065eaf2d772f446ee435758b6ccd276c7d3434`.
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
