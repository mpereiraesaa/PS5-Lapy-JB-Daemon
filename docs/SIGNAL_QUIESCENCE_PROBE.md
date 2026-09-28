# Disposable signal-stop quiescence gate

Build with the installed SDK and `ps5log/1` client:

```sh
python3 tools/build_probe.py --sdk "$PS5_PAYLOAD_SDK" \
  --logging-client ../logging_server/client --probe signal-quiescence
```

Prepared ELF: `build/signal_quiescence-probe/lapy_signal_quiescence_probe.elf`,
build ID `2318aafd54ed30be1e5380595bec884c9d2b0ddbaaf69a24e935c942f2b58d32`,
SHA256 `d77c20df60fe18e2d17a3c0981a3d863ba6a3ef63647ddb825dd94ba720168ab`.

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

A pass establishes that signals quiesce a disposable multithreaded child on
that firmware. It does not establish permission to signal a game, prove that
`ki_stat == SSTOP` alone locks every thread of a different process, or prove
that the game cannot be resumed by another actor during donor transfer.
Before an active-target implementation, verify target identity and prior
state, find a retained process reference or equivalent stop guarantee, check
every thread is suspended and its private filedesc stays stable, and resume
only a process that this daemon stopped. If any gate fails, leave the target
unmodified and acknowledge failure.
