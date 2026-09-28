# Disposable null-jail reference transfer

The donor filedesc probe established that `rfork(RFPROC | RFFDG)` creates two
owned system-root references on the observed 12.02 payload. This experiment
tests whether one of those ownership tokens can be moved into a null jail slot
and then released through another donor's ordinary exit path. It is a
single-run **kernel pointer-write experiment**, not a corrected daemon.

The payload starts with a private filedesc, system root and null jail. It
creates two private children before changing any slot; each child waits on a
pipe. The first child's root slot gives its owned reference to the parent's
null jail slot. The source child then exits, releasing its remaining cwd
reference. The parent moves its jail reference to the second child's null
jail slot, then that child exits. Every step checks the expected pointers and
read-only root-vnode fields. The expected hold/use deltas are `0, +4, +4,
+3, +3, 0` across baseline, both donors, donation, source exit, return and
receiver exit. No vnode counter or credential is written, and no app process
is targeted.

The experiment is bound to firmware 12.02: its `filedesc` reference hint and
root-vnode observation fields are only validated there. The root/jail pointer
offsets come from the installed SDK. Each child has an alarm and the parent
reaps it. Pointer writes occur while both donor children are waiting and all
three filedescs have observed refcount 1. This is a controlled quiescence
assumption, **not** proof that pointer writes are synchronized with every
kernel reader in an active multi-threaded title. A failed write can also leave
one acquired reference to be released at process teardown or, in the worst
case, leak one reference; the probe is not a production rollback mechanism.

Build with the installed SDK:

```sh
PS5_PAYLOAD_SDK=<installed-sdk> python3 tools/build_probe.py \
  --logging-client ../logging_server/client --probe null-jail-transfer
```

Run only under the shared console lease on a clean boot, with the old daemon
stopped and no BigApp. Preserve the private ps5log/1 stream and verify it
against the exact ELF and build manifest:

```sh
python3 tools/analyze_null_jail_transfer.py STREAM.log SERVER.json \
  build/null_jail_transfer-probe/manifest.json \
  build/null_jail_transfer-probe/lapy_null_jail_transfer_probe.elf
```

Success would establish this narrow reference-token transfer in disposable
processes on 12.02. It would not prove an active target can be retained and
quiesced, that its original roots are safely released, that credential
elevation is isolated, or that exit/exec/rfork and `/data` work repeatedly.

## Owned 12.02 result

Build `bcdd5bf51d3db65afdc3947e8423c9164fabe64b5b2cb304542abfd1a5ee2e82`
(ELF SHA256 `b72161c18d41d141bcef2acc621c1e7aa84d7fa955ac2ef9233441f140a6c998`)
passed the identity-bound analyzer with private ps5log/1 stream SHA256
`047725237aa38c03de5aff60218c565dbfe58ec77f9e96bba92ddec214295e25`.
The observed hold/use sequence was exactly `60/59`, `64/63`, `64/63`,
`63/62`, `63/62`, `60/59`; both private donors were reaped, and the parent
finished with a null jail. This supports the token-transfer ownership model
in disposable processes on this firmware. It does not validate concurrent
target modification or a production rollback path.

The same exact ELF then completed 40 consecutive single-run cycles under one
console lease. Every run had a clean artifact-bound ps5log/1 manifest, passed
the analyzer, and began from the same `60/59` baseline; each completed its
full return-to-baseline sequence. The final run's stream SHA256 was
`deb2e7171588db3384dd477e867d6d3377e6772b4754809903673fc83efc1629`.
The private manifest index at `build/null_jail_transfer-probe/stress_summary.json`
was independently revalidated against all 40 saved streams; its SHA256 is
`7a2efc740efd948c7f6f74e357c74468694d6303b8352d2d797cba732397b701`.
The console remained available with no BigApp after the run. This exceeds
the historical 20–29 legacy-elevation count only for this controlled
disposable-process path, not for real app elevation.
