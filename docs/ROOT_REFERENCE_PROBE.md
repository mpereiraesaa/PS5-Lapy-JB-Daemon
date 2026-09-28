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

A follow-up ELF (`8fbf542ecb3c9417750d52a86ba74793c3d6833b22f0bad21c30d5cf56d0dc38`,
SHA256 `0cf6a5ab422e23b71b01841168b6d49a1ee31e2029669a91778a4129061e2aa1`)
also logged its caller identity before the same nine lookups. Under elfldr on
12.02, the caller had real UID 1, effective UID 0, Sony auth ID
`0x480000001000000e`, and capabilities that were **not** all `0xff`; every
lookup still returned `ENOSYS` (78). Thus effective UID 0 does not expose
`kldsym` in this loader context. This does not establish its behavior after a
full Sony capability/auth-ID elevation, nor whether the named kernel routines
exist internally. The private `ps5log/1` stream completed with a clean BYE.

## Native reference calibration without elevation

`--probe root-native-refs` builds a separate disposable ELF. It reads its own
root/jail directory pointers and the SDK's system root vnode, then refuses to
calibrate if `/` might resolve to another vnode. It opens `/` four times with
ordinary `open(O_DIRECTORY)`, keeping each descriptor alive, and closes them
one by one. After each native operation it waits 20 ms and reads only the
32-bit fields at `0x1bc` and `0x1c0`. It never writes kernel memory or changes
another process. Build it with:

```sh
PS5_PAYLOAD_SDK=<installed-sdk> python3 tools/build_probe.py \
  --logging-client ../logging_server/client --probe root-native-refs
```

Verify the stream, server manifest, build manifest and ELF together:

```sh
python3 tools/analyze_root_native_refs.py STREAM.log SERVER.json \
  build/root_native_refs-probe/manifest.json \
  build/root_native_refs-probe/lapy_root_native_refs_probe.elf
```

On owned firmware 12.02, build
`beab8b6b87bacab5cdbc82f6299054b69d60057093dbcd28bf90d818729882ef`
(ELF SHA256 `5234a1754f84d4af0e27c227e1c26cf0659690586cc0dbcad07a80d69dbbc81e`)
completed with a clean `ps5log/1` BYE and no gaps. Its `fd_rdir` was the
system root vnode and `fd_jdir` was null. The values moved from 60/59 to
64/63 through four native opens and returned one step per close to 60/59.
The identity-bound analyzer accepted the exact nine-sample transition. A
separate 120-second read-only baseline had zero field changes. These results
identify two reference-responsive fields in this vnode on 12.02. They do not
show that Lapy's overwritten target fields owned references, prove the
release path for an arbitrary old sandbox root, or validate direct writes to
either field. Other firmware needs its own observation.
