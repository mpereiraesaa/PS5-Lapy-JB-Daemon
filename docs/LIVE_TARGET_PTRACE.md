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
