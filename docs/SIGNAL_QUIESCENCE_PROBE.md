# Disposable signal-stop quiescence gate

Build with the installed SDK and `ps5log/1` client:

```sh
python3 tools/build_probe.py --sdk "$PS5_PAYLOAD_SDK" \
  --logging-client ../logging_server/client --probe signal-quiescence
```

Prepared ELF: `build/signal_quiescence-probe/lapy_signal_quiescence_probe.elf`,
build ID `8c94d11cb37eb01d6ae89950691bf92a117de6e48e8b637c03abab73653cb4d4`,
SHA256 `f55516dcdf5f24143fd88b5c1466dd1411e4e86a36036201d57bd3abe13a8058`.

Under the console lease, run the ELF once through elfldr and retain its
private `ps5log/1` stream. It creates only its own disposable child with two
threads. The parent sends `SIGSTOP`, receives a stopped status through the
native child `waitpid`, reads per-thread `kinfo_proc` states, and confirms a
shared worker counter stays still. It then sends `SIGCONT`, verifies progress
resumes, and reaps the child. It also takes read-only snapshots of that
child's proc structure and reports candidate 32-bit fields with the pattern
`0 → number of threads → 0`. Candidate offsets are diagnostics, not verified
PS5 `p_suspcount` offsets. The ELF does not attach with ptrace, patch a title,
change credentials, or write kernel memory.

The first 12.02 run reached the stopped snapshot but PS5 returned `ENOENT`
for the per-thread `sysctl` request. The revised probe logs that error and
continues only for `ENOENT` or `ENOTSUP`, relying on the child stop event,
stable worker counter and proc snapshots for its disposable-process gate.
It still treats any available per-thread result as mandatory evidence and
rejects a mismatch. On owned 12.02, the revised run completed with
`kinfo_error=2`, a stopped worker counter of `46 → 46`, resumed value `136`,
and one proc-field candidate at `0x3a0` with the observed `0 → 2 → 0`
pattern. This is a disposable-child observation, not an authorized offset
for a game.

A pass establishes that signals quiesce a disposable multithreaded child on
that firmware. It does not establish permission to signal a game, prove that
`ki_stat == SSTOP` alone locks every thread of a different process, or prove
that the game cannot be resumed by another actor during donor transfer.
Before an active-target implementation, verify target identity and prior
state, find a retained process reference or equivalent stop guarantee, check
every thread is suspended and its private filedesc stays stable, and resume
only a process that this daemon stopped. If any gate fails, leave the target
unmodified and acknowledge failure.
