# Disposable ptrace quiescence gate

Build the exact, read-only process-control probe with the installed PS5 SDK:

```sh
python3 tools/build_probe.py --sdk "$PS5_PAYLOAD_SDK" \
  --logging-client ../logging_server/client --probe ptrace-quiescence
```

The prepared ELF is
`build/ptrace_quiescence-probe/lapy_ptrace_quiescence_probe.elf`, build ID
`06235c0c6924440df9905e758e5c52d020f6cd8aa38ef8f67ce5bca33250afd6`,
SHA256 `7d7107f43e32cf36ad6b91cc9fd4e46d78de37a4762f8697d375c783982bf8a3`.
Run it once through elfldr under the console lease and keep its private
`ps5log/1` stream. It creates only its own disposable child with a worker
thread, attaches that child with `PT_ATTACH`, waits for a stopped status,
checks `PT_GETNUMLWPS`, `PT_GETLWPLIST` and `PT_GETREGS`, and confirms that a
shared tick counter stays still while attached and advances after detach.
No title process is attached, no kernel memory is written, and no credentials
or directory roots are changed.

Passing this gate would establish only that a standalone elfldr payload can
quiesce **its own disposable multithreaded child** on this firmware. It is not
permission to attach a game. The local `ps5debug-NG` README says PS5's
AppContext gating makes standalone `PT_ATTACH` on game PIDs leave the game
flagged and unable to progress; its debugger runs inside SceShellCore to
avoid that. A real Lapy target therefore still needs a separately validated
stop/resume path or an SCE-origin attach. The donor reference probes already
validated ownership transfer in disposable filedescs, but they do not prove
quiescence, target retention or credential isolation in a live title.
