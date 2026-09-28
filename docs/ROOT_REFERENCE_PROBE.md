# Root vnode reference observer for a console session

This is a read-only, bounded probe. It **does not fix or deploy Lapy** and
cannot establish the correct `vrele` implementation by itself. Build it with:

```
PS5_PAYLOAD_SDK=<installed-sdk> python3 tools/build_probe.py \
  --logging-client ../logging_server/client --probe root-refs
```

The builder freezes the SDK, source, compiler flags and logger header into a
build ID, hashes the ELF, and writes an ignored manifest. The same ELF uses the
SDK's per-firmware rootvnode address when available, or reads init's root
through the SDK's per-firmware process and filedesc accessors. The probe never
writes kernel memory. It reads the first 0x1c4 bytes of the root vnode once per
second for 120 seconds, emitting only changes of small 32-bit values through
ps5log/1. The SDK FreeBSD header suggests hold/use fields at 0x1bc/0x1c0; the
log labels these hints **unverified** and prints their values only when both
look like small counters. Otherwise it records `status=unavailable` without
field values. No kernel pointer values are transmitted.

After console recovery, use a **clean boot** and the shared `console:PS5`
lease. Run at most a few ordinary launch/close escalations during the bounded
probe; the previous boot panicked by elevation 29. Preserve the matching
ps5log stream and artifact manifest privately. A counter decreasing in lockstep
with exits supports the missing-reference hypothesis; unrelated 32-bit fields
can also change and absence of a match does not falsify it. Stop on any error,
unexpected reboot, malformed logger stream or changed root identity.
The host-side `tools/analyze_root_refs.py LOG SERVER_MANIFEST BUILD_MANIFEST`
verifies artifact/build identity, stream completeness, hash, record sequence,
and probe completion before summarizing candidate offsets and net changes.
Its output is a private observation, not proof of a vnode field's meaning.

The observer does not verify vnode layout, kernel lock ordering, filedesc
unsharing, or native release semantics. It cannot justify a guessed `+2` write.
The final solution still needs one verified per-firmware kernel adapter that
retains the target, unshares/locks its filedesc, acquires destination references,
publishes both pointers, and calls the native release path for old references.

## Kernel symbol lookup, before attempting a text-side debugger

`--probe kernel-symbols` builds a second, short, **lookup-only** ELF. It invokes
the native `kldsym(0, KLDSYM_LOOKUP, ...)` syscall with checked carry/error for
`copyin`, `copyout`, `vref`, `vrele`, `fdunshare`, `fdcopy`, `sx_xlock`,
`sx_xunlock`, and `proc_rele`. FreeBSD documents fileid 0 as searching all
loaded modules. PS5 may reject lookup or omit these symbols; this probe tests
that possibility without calling any returned address. The logger receives
only name, error, canonical-pointer classification and reported symbol size.
An observed symbol does not prove its calling convention, lock ordering, or
that it is safe to invoke from Lapy; a missing symbol does not prove the
function itself is absent. This path may allow runtime multi-firmware symbol
resolution **if** another firmware exposes suitable symbols.

On owned firmware 12.02, the corrected probe build
`a0b230010a01b8bb21b2c4e2e33ce849d3d5875247fc569713503d5cdde2d89c`
(ELF SHA256 `33e14b050e51eab5613d0d447ebd2006e2aee19873d6e5ba72061b228133726d`)
logged all nine valid symbol names and their nonzero lengths, with `ENOSYS`
(78) for every `kldsym` call. The private `ps5log/1` session has a clean BYE
and no sequence gaps. This closes the `kldsym` lookup path on
12.02, not the possibility of a different native adapter. The first probe
build used a static pointer table whose entries appeared null at runtime, so
its nine `ENOSYS` results alone were ambiguous; the corrected build passes
each name literal directly and logs it alongside the result.
