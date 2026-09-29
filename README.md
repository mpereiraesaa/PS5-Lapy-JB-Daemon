# PS5 Lapy JB Daemon — owned-root fork

This fork provides a resident elevation daemon for PS5 firmware supported by
the payload SDK. It is intended for homebrew that repeatedly launches processes
needing `/data` access, such as a launcher starting games. **Only firmware
12.02 has been validated on a console.** Other versions are experimental: the
daemon checks its assumed kernel layout with native `getgroups` and a
disposable child before changing a target, and refuses to proceed if the
checks fail. The old backend
is available only through the explicit `make legacy` target.

Legacy Lapy directly overwrites a process's root and jail pointers. Repeated
use on our console was associated with a panic after roughly 20–29 elevations
per boot. This daemon transfers two root vnode references obtained by native
`rfork` into the target; native donor exit releases its displaced sandbox
roots. It also requires the target to clone its own credentials before the
request. See [the design and evidence](docs/OWNED_ROOT_DAEMON.md). The crash
mechanism is strongly suggested by the evidence, but no kernel dump proved it.

Donor startup and release now use process signals and `waitpid`, with no
per-request pipes. On FW 12.02, a fresh pipe could be created but writing one
byte to it failed with `ENOMEM` after sustained use; the older daemon then
lost its donor acknowledgement and exited. The signal-controlled candidate
completed four cooperative `/data` elevations in that same boot while fresh
pipe writes still failed. This avoids that immediate failure path; it does not
identify or repair the kernel's pipe allocation problem.

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
