# Release a displaced non-system root through a native donor

The null-jail transfer probe showed that a donor's owned system-root
reference can fill a null jail slot and be released through normal filedesc
teardown. A corrected Lapy also has to release each **old, non-null** root it
replaces. This one-shot experiment tests that release in disposable processes
on firmware 12.02.

The payload starts with a private filedesc whose root and cwd are the system
root and jail is null. One private donor uses native `chdir("/data")` to own a
reference to the `/data` directory in its cwd slot; a second donor retains a
system-root reference. While both children wait on pipes, the payload
exchanges its root with the first donor's cwd. The first donor now owns the
payload's former system root and releases both of its root references at
exit. The payload's root temporarily names `/data`, with its original `/data`
reference still owned. It exchanges that root with the second donor's system
root. The second donor exits and releases the displaced `/data` reference.
The payload ends with the original root, cwd and null jail.

The candidate cwd slot at `filedesc + 0x08` and vnode observation fields at
`0x1bc`/`0x1c0` are restricted to the observed firmware 12.02. The probe
checks the target and both donors have private filedescs (observed reference
hint 1) and checks every root/jail pointer before writing. It never edits a
vnode counter or an active app process. A failed pointer write is not a
production rollback guarantee; the probe's quiescence assumptions do not
cover a multi-threaded title.

Build and run only with the installed SDK, shared console lease, no BigApp and
the lab's ps5log/1 server:

```sh
PS5_PAYLOAD_SDK=<installed-sdk> python3 tools/build_probe.py \
  --logging-client ../logging_server/client --probe old-root-release
python3 tools/analyze_old_root_release.py STREAM.log SERVER.json \
  build/old_root_release-probe/manifest.json \
  build/old_root_release-probe/lapy_old_root_release_probe.elf
```

The analyzer requires the system-root hold/use deltas `0, +1, +3, +3, +1,
+1, 0` and requires the observed `/data` vnode fields to decrease by exactly
one only when the second donor exits. Passing would establish one controlled
old-root release, not a working daemon, multi-firmware behavior, active-target
synchronization, or repeated `/data` access through exit/exec/rfork.

## Owned 12.02 result

Build `82c20bb530491402f8179b52cbf1c3aeadc0e69be040e21ecf0f3544abeeccb3`
(ELF SHA256 `bc022369de740da90264a2a7158c62bdf3bdb353c4cf86f0395ece65569b886d`)
passed the identity-bound analyzer with private ps5log/1 stream SHA256
`f1d92db9a8f0c0d672db954575839dbf53fa489611e9aa76fee8e01fd53a2fc0`.
The root-vnode hold/use sequence was `60/59`, `61/60`, `63/62`, `63/62`,
`61/60`, `61/60`, `60/59`; the `/data` vnode stayed at `3/3` while its
reference was held and fell to `2/2` after the replacement donor exited.
Both donors were reaped and the console remained responsive.

The exact ELF then passed 40 consecutive runs under one console lease. Every
saved stream passed the analyzer, with the same root baseline `60/59`,
`/data` acquired sample `3/3` and final sample `2/2`. The private manifest
index at `build/old_root_release-probe/stress_summary.json` was revalidated
against all 40 streams and has SHA256
`a15be50e9f191bf7531496b39dc591d0370e33e7c437fb67635fafa96e4f7588`.
This demonstrates repeated controlled old-root release in disposable
processes only; it does not establish safe active-title modification.
