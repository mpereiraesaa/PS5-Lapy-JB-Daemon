# Native credential replacement gate

Build with the normal SDK and logging client:

```sh
PS5_PAYLOAD_SDK=/path/to/sdk/install python3 tools/build_probe.py \
    --logging-client /path/to/logging_server/client --probe credentials
```

Output is separate under ignored `build/credential-probe/`. Deployment requires
the same exclusive console coordination and exact artifact/evidence mapping as
the transport probe. The program uses native `seteuid` with its existing euid,
up to 64 times. It does not elevate, chroot, create children, alter another
process or write kernel fields directly. SDK/loader startup remains external.

Each iteration requires a different current credential pointer and unchanged
uid/euid/gid/egid, Sony authority/capabilities/attribute byte, root and jail
directory pointers. Reads use SDK-provided offsets and APIs. An old credential
pointer is compared as an opaque value only, never dereferenced after seteuid.
No kernel pointers or privilege values are logged.

Require a clean ps5log/1 session with matching build identity and firmware,
`stage=complete error=0 completed=64 replacements=64 expected=64`, BYE and no
sequence gaps. Replacement plus preserved fields is a necessary capability
observation, not proof of reference counts, exclusive credential ownership,
uid-accounting correctness after elevation, remote execution context or exit
safety. An unchanged pointer is inconclusive about implementation but fails
this gate; it must never authorize subsequent in-place credential edits.

## Observed result on 12.02

Build `3610be82a47dc6c9a0f89dbc69c216cbbdbfa71262cdf4c8e8febfd7e644862c`,
ELF SHA256 `eb72e709aacd9f625f24a1f22a58f83651698939f933ea116c05bec931e80cf3`,
completed 64/64 with 64 consecutive credential-pointer replacements and all
checked fields preserved. The ps5log session ended with clean BYE, no gaps;
its private log SHA256 is
`607dba28d90fd58ca790ab3d3ab098cf5ba26c1ededc2f5eab4cb6f37f81a397`.

An earlier probe stopped before seteuid because it treated NULL root/jail
pointers and SDK read failures identically. The current probe checks the
underlying copyout result and permits a successfully read NULL directory
pointer. This does not weaken the unchanged-state check. All results apply to
the loader's payload process, not a sandboxed game or a multithreaded target.
