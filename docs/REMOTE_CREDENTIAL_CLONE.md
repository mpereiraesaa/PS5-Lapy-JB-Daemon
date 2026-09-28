# Remote native credential clone probe

Lapy currently edits the target's `ucred` directly. The corrected daemon needs
a native credential replacement in the **target** before changing UID and Sony
fields. Calling `seteuid` in the daemon clones the wrong credential. This
one-shot FW 12.02 probe prepares a disposable child and a three-byte executable
`syscall; int3` gadget inside that child. The host debugger verifies those
bytes, stops its sole thread, runs native `seteuid` (syscall 183) with its
unchanged effective UID, checks the syscall result, restores every original
register, and resumes. The parent payload reads the child's process credential
before and after, requires a different pointer with UID and Sony fields
unchanged, then verifies normal child exit. Neither path writes a credential
pointer or any kernel memory directly. No homebrew title is touched.

Build offline:

```sh
python3 tools/build_probe.py --probe remote-credential-clone \
  --sdk /path/to/ps5-payload-sdk/install \
  --logging-client ../logging_server/client
```

The prepared build ID is
`a57e805235bbf53f19f400048749e525718bf694b2047d0b4d5b7e9c74a2ddb5`
and ELF SHA-256 is
`cee010cf898e9a70aaf9a65b984e4c85eb873809abf0ff1aa2cddb6effe84df2`.
These identify the compiled probe only, not console validation. The gadget
address is logged only in the private `ps5log/1` stream; do not publish raw
addresses or that stream.

In an attended next console session, start the logging server, read the shared
mailbox, acquire `console:PS5` on an idle console and run:

```sh
python3 tools/run_remote_credential_probe.py --host "$PS5_HOST" \
  --ps5debug-python /path/to/rehd_mods
```

The coordinator checks the ELF hash, a fresh stream and the gadget's actual
bytes before any register change. It requires one thread, successful syscall,
full register restoration, parent-observed credential replacement and clean
`BYE` after child exit. If stepping or restoration is uncertain it keeps the
child/debugger stopped for manual recovery; do not kill the coordinator in
that state. No daemon should be running during this test.

A passing run would establish the remote native clone method only for this
controlled child. Before using it on a title, the daemon still needs retained
process identity, all-thread stop and per-thread credential behavior checks.
The target's private clone would allow UID/Sony changes without editing a
shared old credential; no prison pointer should be changed directly. The
separate two-root transaction must also pass its console gate and then be
integrated with the credential path and repeated title lifecycle tests.
