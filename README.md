# PS5 Lapy JB Daemon — owned-root fork

This fork provides a resident elevation daemon for PS5 firmware supported by
the payload SDK. It is intended for homebrew that repeatedly launches processes
needing `/data` access, such as a launcher starting games. The resident service
has repeat validation on firmware 12.02. Its target-lifetime fix and full
transaction have also been exercised on firmware 12.70, while the one-shot
helper's donor lifecycle was tested on firmware 6.02 and 12.70; see
[Validation and limits](#validation-and-limits). Other versions are
experimental: the daemon checks its assumed kernel layout with native
`getgroups` and a disposable child before changing a target, and refuses to
proceed if the checks fail. The old backend
is available only through the explicit `make legacy` target.

Legacy Lapy directly overwrites a process's root and jail pointers. Repeated
use on our console was associated with a panic after roughly 20–29 elevations
per boot. This daemon transfers two root vnode references obtained by native
`rfork` into the target; native donor exit releases its displaced sandbox
roots. It also requires the target to clone its own credentials before the
request. See [the design and evidence](docs/OWNED_ROOT_DAEMON.md). The crash
mechanism is strongly suggested by the evidence, but no kernel dump proved it.

Donor startup and release use `SIGSTOP`, `SIGKILL`, and `waitpid`, with no
per-request pipes or user-space signal handler. On FW 12.02, a fresh pipe could
be created but writing one byte to it failed with `ENOMEM` after sustained
use; the older daemon then lost its donor acknowledgement and exited. An
intermediate `SIGUSR1` exit handler avoided pipes, but its payload children
faulted during signal delivery on FW 6.02. Native `SIGKILL` teardown avoids
both firmware-dependent paths while still closing each private donor filedesc.

## Required cooperation in the homebrew

The request file is **`/download0/elevate_proc`**. It replaces the old
`etahen_jailbreak` marker. In the **same process** that needs elevation, call
`seteuid(geteuid())` before creating other threads and before writing the
request. Check its return value. Then write a JSON request containing that
process's PID. [The C example](examples/cooperative_elevation.c) shows the
minimal integration; [the tested Hello World main](examples/cooperative_hello_main.cpp)
shows the full request and `/data` read/write check.

```c
if (seteuid(geteuid()) != 0)
    return -1; /* Do not request elevation. */
/* Now create /download0/elevate_proc containing {"PID":<getpid()>}. */
```

The same-UID call asks the kernel to give **this homebrew process** a private
credential. Calling `seteuid` in the daemon would clone the daemon's
credential, not the target's. The daemon rejects a target unless it sees the
expected private credential, one thread, private filedesc and prison state.
Marker consumption alone does not prove success: check actual `/data` access
before using it. The title must enable `downloadDataSize` for `/download0`.
Only run one Lapy daemon. Old homebrews must adopt the new protocol; this
fork does not silently fall back to the legacy kernel writes.

## Build and run

Use a PS5 payload SDK and a `ps5log/1` client alongside this checkout:

```sh
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make check
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make owned-service
```

The ELF is `build/owned_root_daemon-service/lapy-root-daemon.elf`.
Load it once via an ELF loader; it stays resident and watches `PPSA*` requests.
For a bounded diagnostic build, pass `--service --max-requests N` to
`tools/build_owned_daemon.py`. The daemon emits machine-readable `ps5log/1`
events, including completion and reference-balance fields.

## Validation and limits

On one owned **FW 12.02** PS5, a one-request build completed **32/32**
consecutive launch → elevate → `/data` read/write → close cycles in one boot.
Every cycle reported balanced root counters. A bounded resident build then
handled **5/5** requests in one daemon process, with `/data` read/write
confirmed after each. A later guarded resident request also passed. The
runtime layout preflight then passed on 12.02 and another resident request
completed with `/data` read/write. Those
finite test ELFs and hashes are in the design record. The published unbounded
service ELF is built from this source; it has not been exercised indefinitely.

The runtime check can reject a firmware whose layout or native reference
behavior differs; passing that check is not a substitute for an attended
repeatability test on that firmware. Other homebrews, multithreaded callers,
concurrent daemons and
unusual exit or exec paths are not established by these trials. Historical
source research is in [ELEVATION.md](docs/ELEVATION.md). License terms are in
[LICENSE](LICENSE).

On FW 12.70, a disposable title confirmed that the previous daemon could
cache a live `proc` together with already released `filedesc` and `ucred`
pointers before ptrace attachment. The daemon now observes the ptrace stop
before its first target snapshot. Under the same forced two-second window,
all identities remained current and the complete elevation transaction
succeeded without a kernel panic. The exact reproduction, artifact hashes,
and limitation of that result are in
[the target exit-lifetime record](docs/TARGET_EXIT_LIFETIME.md).

The one-shot payload also binds each request PID to the title ID of the
sandbox containing the marker, checks that identity again after stopping the
process, and refuses to detach unless donor teardown leaves exactly two native
system-root references. On FW 12.70, the hardened one-shot completed `/data`
read/write and returned root counters to baseline after title exit. A separate
PID-2 request was rejected at the identity check before ptrace or any kernel
mutation.

The `SIGKILL` donor-release one-shot helper was additionally tested through an
integrated exact-title caller for **5/5 cycles on FW 6.02** and **5/5 cycles on
FW 12.70**. Every cycle reported successful `/data` access as root,
`donors_reaped=1`, and `donor_balance expected_two=1`; the helper exited
normally and the captured kernel-log windows contained no fatal signal, app
crash, coredump, nonsleeping-lock warning, or kernel panic. The tested helper
had build ID
`70c935c0b1c28730eee3fff49d6d9dc0978ee68842d15edeafbd49d4b33de318`
and SHA-256
`cac3987ef3c25e9fccbb2c5aca94fab106f91c16828ae5d91048718dde610379`.
This qualifies that exact one-shot integration; it does not turn every SDK-
supported firmware or caller lifecycle into a supported configuration.

## One-shot elfldr helper

For a homebrew that already owns its startup flow, the same transaction can
run as a one-request ELF helper instead of a resident daemon. The caller sends
this ELF to the local elfldr listener on port 9021 and holds the connection
open for the versioned prepare/result exchange. It must call
`seteuid(geteuid())` in the target process after the helper's prepare message;
the helper validates the exact title and PID before applying the existing
owned-root transaction. The helper exits after its response. This mode still
requires the caller-side protocol implementation and is built for one exact
title ID.

Build the helper and its release manifests with:

```sh
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk \
  make owned-helper TARGET_TITLE=PPSA99995
```

The output is `build/owned_root_helper-PPSA99995/lapy.elf`. The directory also
contains `manifest.json` for local build records and `lapy-manifest.json` for
publishing alongside `lapy.elf` as release assets. The release manifest
records the ELF and shared protocol hashes, target title, build mode, and the
`root_layout_probe_retry` feature. Consumers should reject assets missing
that feature or whose title, ELF digest, or protocol digest does not match.

On one FW 12.02 console, the helper builds with this feature completed 32/32
elevation attempts for PPSA99995, including 30 consecutive launcher
launch/close cycles. Every attempt reported balanced root counters and the
title confirmed `/data` access. In one of the 20 most recent cycles, an
inconclusive first counter probe retried once and then completed successfully.
Other firmware versions and titles remain unvalidated.
