# Payload-side ptrace retention of a real title

This FW 12.02 diagnostic waits for a fresh `PPSA99994` Hello World request,
checks the target PID and private `filedesc`, and natively clones only its own
credential before selecting the temporary ptrace authority. It calls
`PT_ATTACH` on the title and waits for the kernel's stop event. Two target
snapshots must retain the same proc, filedesc and thread members, with all
threads suspended. It then detaches, sends `SIGCONT`, restores its own Sony
authority and acknowledges the request. It does not change the title's
credential, root or jail and performs no kernel write to the title.

This test separates the payload-side ptrace route from ps5debug-NG's host
event dial-back, which prevented the previous retained-reference probe from
starting. A successful result would establish a retained identity and stable
stop for this one real title; it would not establish root-reference ownership,
credential cloning inside the title, or repeated-elevation safety. A failed
`PT_ATTACH` returns a normal failed stream. If attach succeeds but the stop
state or detach becomes uncertain, `probe_held` keeps the payload alive for
attended repair; do not kill it or launch more titles before inspecting state.

Build with the installed SDK and logging client:

```sh
python3 tools/build_probe.py --probe live-target-ptrace \
  --target-title PPSA99994 --sdk <installed-sdk> \
  --logging-client ../logging_server/client
```

The offline FW 12.02 artifact is
`build/live_target_ptrace-probe/PPSA99994/lapy_live_target_ptrace_probe.elf`.
Build ID: `ecf9251598998362dc838a8cd8a05db5f24cf4fb2c0a5b0c17e17e805119727a`;
ELF SHA-256:
`95df2248f72aa713d1818221c4a68cd4970c7c96fd7cec83aba4e9dba53fa891`.
Under the lab's `console:PS5` lease, send the probe once through elfldr, then
launch the isolated Hello World title. Collect its private `LAPYTP`
`ps5log/1` stream and server manifest, and close the title after the request
is acknowledged. Do not run the legacy Lapy daemon concurrently, because it
polls and consumes the same request marker.

The first owned-console cycle passed on FW 12.02. The `LAPYTP` stream
`20260928T095303966Z_LAPYTP_lapy-live-title-ptrace-retention_0x2395b12fc998`
has SHA-256
`fa46ecaceb835898f3d72aa89024da35d3848bae9b999137c6db381943eacff1`;
its server manifest reports clean, gap-free `ps5log/1` with three records and
BYE. Target PID 1158 retained its proc/filedesc identity, had private
`fd_refcnt=1`, and had its one linked thread suspended in both snapshots.
`PT_DETACH`, parent authority restoration and marker acknowledgement all
succeeded. The title then closed normally; no payload remained. This is the
real-title retained-stop gate for the next credential/root transaction probe,
not yet an elevated title.

## Read-only syscall location check

Build `--probe live-target-ptrace --target-title PPSA99994 --scan-gadget` with
the same SDK and logging client to get the isolated artifact under
`build/live_target_ptrace-probe/PPSA99994/scan/`. It adds `PT_GETREGS` and
read-only `PT_READ_I` checks over the nearby code pages of the stopped title.
It first searches near the stopped RIP. If that fails, it scans the first
code page at the `libkernel.sprx` base observed by the host map inspection.
It reports only whether a two-byte `syscall` instruction was found, its
distance from the RIP or libkernel base, and which region supplied it. It does
not log target addresses, set registers, execute that instruction or mutate
target memory. It detaches, restores tracer authority and acknowledges the
request as before.

Prepared FW 12.02 build ID:
`0445b318338ef6b45479fdf0b54f81542bf22c465b472f329ba29b66ad555ae7`;
ELF SHA-256:
`4e7b102acc3a033a6bd8245fa696adc207f59d3adeb3fa84212172f7a2232c94`.
This build was run once on the console. Its clean `LAPYTP` stream is
`20260928T100058472Z_LAPYTP_lapy-live-title-ptrace-retention_0x24042bec9404`.
For the title's mapped `libkernel` offset `0xf8`, payload-side `PT_READ_I` and
`PT_READ_D` each returned `0x0000000c` with `errno=0`; neither returned the
actual `89 ca 0f 05` bytes observed through ps5debug's read-only process-map
API. The scanner therefore found no gadget even though 5,120 reads returned
without errno. It detached, restored authority, acknowledged the request and
closed the title cleanly. No target register or memory write was attempted.
This rules out using this `ptrace` read route as a safe gadget verifier on this
title without further investigation.

An earlier RIP-near-only run completed and detached cleanly but found no
`syscall` in nine nearby pages. A separate read-only host inspection of the
same title showed executable `libkernel.sprx` at `0x800000000` with a `syscall`
byte pair at offset `0xfa`. The first fallback build incorrectly required the
loaded code segment to begin with an ELF header and therefore reported a false
negative; it detached and closed cleanly. The revised scan made 5,120
successful `PT_READ_I` calls but still missed the opcode. A second host map
read confirmed that the base did not move and the bytes at offset `0xf8` are
`89 ca 0f 05 72 0d 89 07`. The current diagnostic logs the low word and
errno from both `PT_READ_I` and `PT_READ_D` at that address to distinguish
different ptrace read semantics from an address or scan error.
