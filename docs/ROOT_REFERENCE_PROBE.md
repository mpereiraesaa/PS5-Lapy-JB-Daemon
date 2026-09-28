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
log labels these hints **unverified**. No kernel pointer values are transmitted.

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
resolution **if** the console exposes suitable symbols, but no such result
has yet been observed.
