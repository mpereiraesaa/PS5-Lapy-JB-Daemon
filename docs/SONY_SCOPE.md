# Scoped Sony privileges on a replaced credential

`sony_scope.c` requires native credential replacement before changing the Sony
authority and capability fields. It rejects unchanged or missing identity,
tracks possible partial writes, verifies readback, and restores the saved
fields on end. Failed restoration leaves the scope active and is an unresolved
error. It never edits UID, group, prison, directory or reference-count fields.

The caller must exclude fork/exec and competing credential changes throughout
the scope. A changed pointer does not establish exclusive ownership by itself.
The current adapter operates only on the non-forking probe process and checks
its current credential before every read/write. This does not implement safe
remote process control. Callers must invoke end even when begin fails.

The native adapter clones via seteuid(current euid), then uses SDK offsets to
read/write only Sony authority and 16 capability bytes. No old credential is
dereferenced after replacement. The original fields are restored with readback;
the native replacement itself is retained and cleaned up through process exit.

```sh
PS5_PAYLOAD_SDK=/path/to/sdk/install python3 tools/build_probe.py \
    --logging-client /path/to/logging_server/client \
    --probe cross-root --sony-privileges
```

This mode is explicit and encoded in artifact identity and telemetry. The
default probe does not change Sony fields. Build does not deploy. Acquire the
console lease and require exact artifact mapping plus complete ps5log evidence.

Host fault tests cover failed clone, unchanged credential, failed snapshot,
partial writes, corrupt readback, stale identity, failed restoration, and
idempotent end. ASan/UBSan and the existing transport checks pass.

## Native observation

On 12.02, build
`f04dad22e65aa6a74f3d318b8a4d6d19288d1d1beb9c3dc9b11d837cebef67ec`, ELF
`ed860546bee1e6548cb5f25564c12780b198ad2a896590315f85dc71b3df0d3f`,
confirmed native credential replacement, full Sony capabilities and system
authority, but chroot(/data) still returned EPERM before any root change.
Sony restoration completed with readback and error zero. The ps5log session
has clean BYE, no gaps, and private log SHA256
`c77daf80346df7586403d23d82d891b49d1afa9be4004578dd4576cd8c313c52`.

Therefore this privilege profile alone does not unlock chroot in the observed
process. Native real/saved identity, prison restrictions and the actual Sony
permission check remain to be investigated. This component is not a complete
elevation backend or proof of exit/exec/rfork safety.
