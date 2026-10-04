# Owned-root Lapy daemon

The corrected backend is `source/owned_root_daemon.c`. On tested firmware 12.02 it
replaces the legacy direct root-pointer overwrite with a transfer of **two
native vnode references**. Two disposable `rfork(RFPROC|RFFDG)` children each
inherit a system-root reference. While the requested title is stopped, Lapy
moves those references into its `fd_rdir` and `fd_jdir` slots, and moves the
title's two old root/jail references into the donor filedescs. Native donor
exit releases the old references. The title owns the system-root references
until its own exit or exec cleanup releases them.

Donor readiness uses a pipe-free handshake. Each child calls
`kill(getpid(), SIGSTOP)` and waits. The parent receives the stop through
`waitpid(WUNTRACED)`, resumes the child, verifies its live process state, and
later sends `SIGKILL` and accepts only that exact termination status. Native
process teardown closes the private donor filedesc and releases its directory
references. The parent still uses `SIGSTOP` to quiesce donors
during the root transfer. On FW 12.02, `raise(SIGSTOP)` returned an error in a
disposable probe, so the child uses the native `kill` route. An intermediate
`SIGUSR1` exit handler faulted during payload signal delivery on FW 6.02;
`SIGKILL` requires no user-space signal trampoline. Any unexpected child state
or timeout fails closed.

A title must prepare its credential **before** writing the
`/download0/elevate_proc` request. This is a protocol change from legacy Lapy;
the old `etahen_jailbreak` marker is not accepted by this backend:

```c
if (seteuid(geteuid()) != 0) {
    /* Do not request elevation. */
    return -1;
}
/* Write the existing JSON PID request here. */
```

This call keeps the same UID; it asks the kernel to replace a shared `ucred`
through its native path. On the tested console, the unmodified Hello World
arrived with `cr_ref=105`; after this call it arrived with `cr_ref=2` (one
process and one thread reference). The daemon discovers the thread credential
slot from its own natively cloned credential, then requires the same pointer
relationship, `cr_ref=2`, one thread, a private filedesc and unchanged target
identity before editing any target credential. It also requires the title to
already reference `prison0`; this backend does not swap prison pointers.
An unmodified title is rejected
before target credential or root writes. The title should call `seteuid` early,
before it starts more threads. It must check the return value.

The resident service scans `PPSA*` sandbox requests and handles successive
titles without restarting. A bounded one-request mode remains available for
controlled tests. The SDK resolves its kernel addresses by firmware; the
daemon also checks its assumed process layout, compares the raw `cr_ngroups`
field with native `getgroups`, and validates the vnode counter offsets through
a disposable native `rfork` child before changing a target.
It fails closed if those checks fail. The layout and lifecycle have been
validated on **FW 12.02 only**; other SDK-supported firmware is experimental.
It does not silently fall back to `Hijacker::jailbreak(true)`.

If the launcher closes a requested title before any root slot is touched,
the daemon now verifies that the original process identity has disappeared,
reaps the two untouched native donors, and continues watching requests. A
missing request marker is expected when the title's sandbox has already gone.
If the original title is still present but credential restoration or ptrace
detach fails, or if a root slot may have been touched, the daemon retains the
`daemon_held` stop rather than guessing ownership. `target_drift` records the
pre-transfer snapshot differences for diagnosis. This recovery path has not
yet been exercised by a targeted title-exit race on the console.

Build with the installed SDK and the lab's `ps5log/1` client:

```sh
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make owned-service
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make owned-one-shot
```

The resident ELF is
`build/owned_root_daemon-service/lapy-root-daemon.elf`. The
one-request build defaults to `PPSA99994`; the build script also accepts
`--title PPSA12345`, or `--title '*'` with `--service`. For a finite lab run,
pass `--service --max-requests N`; add `--require-client-result` only when the
test homebrew implements the temporary result-file handshake. Run only one
Lapy daemon at a time.

The daemon reports every stage over `ps5log/1`. A successful request needs
`credentials_applied`, `roots_committed`, `donor_balance expected_two=1`, and
`request_result stage=complete error=0`. In the one-request validation mode it
also waits for the title to close and for the root vnode counts to return to
the pre-request baseline, then reports `root_balanced=1`. The resident service
does not wait for title exit; long-running homebrews can keep playing while
later requests arrive. `daemon_held` means ownership was ambiguous after a
critical step: leave that payload and title in place for attended diagnosis.

On the owned FW 12.02 console, the one-request build completed **32/32**
consecutive launch → elevation → `/data` read/write → close cycles in one
boot. Every cycle returned the root counters to `hold=69, use=68` and ended
with a clean `ps5log/1` BYE. The tested ELF SHA-256 was
`f779cd10652dfae4409abd6d5143f7243acdef72c03e433f9ef9376561d7fd42`.
A bounded resident build then handled **5/5** requests in one daemon process,
with `/data` read/write confirmed for each; after the last close an independent
root sample again read `69/68`. Its ELF SHA-256 was
`d1f0592a8ce1677c369f705761dc8aa985c09639ef2620403c36bedd681f7367`.
After renaming the marker to `elevate_proc`, a bounded resident build handled
one more cooperative title on FW 12.02: private target credential, prison0,
two native root references, `/data` read/write and clean `ps5log/1` BYE were
observed. That test ELF SHA-256 was
`df542cb97fcd0a4f905c133c344fddd5f9fb5f01f5554e4bd5eee04c56abf055`.
The unbounded release ELF is a separate build of the same source and is not
claimed to have completed an unlimited-duration hardware run.
With the SDK-supported firmware gate and the new preflight layout check, a
bounded resident build completed another FW 12.02 request. The disposable
child changed root hold/use from `69/68` to `71/70`, and native exit returned
them to `69/68` before the target was touched. The request then completed
with `/data` read/write confirmed and a clean `ps5log/1` BYE. The tested ELF
SHA-256 was
`134ada7f2b4a059f943a19a40fd66e07bb7ccd0fbca17928142efc5831e2c188`.
With the final group-field guard, native `getgroups` matched the stored field;
the root layout check and a further `/data` read/write request also passed.
That bounded ELF SHA-256 was
`dc5b0aee1102d7f7aab6ccee65992dfdcb2144293b5eebb65829ba880ad8a554`.
No other firmware was available for this test; passing the runtime preflight
there must not be presented as completed console validation.
The temporary test title was restored to its original `eboot.bin` SHA-256
`b62386902cef054114c1f3ae80bd5b665c175b0fb1a11c5b10e6d19d057fc5e3`.
Private run logs and artifact hashes remain in the lab; they are not packaged
into the public fork.

The cooperative test title preopened a result file in `/download0` before
elevation and wrote its `/data` read/write result through that descriptor
after the root changed. The daemon relayed that result to `ps5log/1`; the
result file was IPC, not a log sink. Existing titles can likewise retain an
open descriptor to a sandbox resource across the root change.
The exact test `main.cpp` is preserved as
`examples/cooperative_hello_main.cpp`; it is meant to replace `src/main.cpp`
in a separate `ps5-native-app-boilerplate` checkout with the lab's `ps5log.h`
available in that checkout's `src/`. The boilerplate itself is not copied
into this fork. Its test package needs `downloadDataSize > 0` and a private
`dev.conf` for the logging endpoint. Back up any installed test title before
deploying a rebuilt `eboot.bin`.

The outstanding work for other firmware is an attended repeatability test of
the runtime layout check, filedesc, thread, credential and vnode behavior.
Other homebrews must adopt the cooperative `seteuid` call, or a
future daemon must find a separately validated native target-clone method.
The payload-side `PT_READ_I` and `PT_IO` attempts did not return usable target
code bytes on this firmware, so they are not used for target cloning here.

The `SIGKILL` donor-release helper was later qualified in one exact-title
one-shot integration on FW 6.02 (`06020004`) and FW 12.70 (`12700001`). The
same ELF (build ID
`70c935c0b1c28730eee3fff49d6d9dc0978ee68842d15edeafbd49d4b33de318`,
SHA-256
`cac3987ef3c25e9fccbb2c5aca94fab106f91c16828ae5d91048718dde610379`)
completed five launch/elevate/close cycles on each console. All ten requests
reported `stage=complete error=0`, `donors_reaped=1`, and
`donor_balance expected_two=1`; the callers independently proved `/data`
read/write access with uid/gid `0/0`. Each helper emitted
`reason=daemon-complete`, its payload exited normally, and the captured kernel
log windows had no fatal signal, app crash, coredump, nonsleeping-lock warning,
or kernel panic. The console services remained responsive after each cycle.
This validates the corrected donor release on both tested firmware families,
not every firmware or arbitrary caller behavior.

On a later FW 12.02 boot, the pipe-based resident daemon completed 55
requests and then failed while starting its second donor. A fresh pipe write
returned `ENOMEM` even in a standalone parent process before `rfork` or
credential cloning; both the installed 0.2.1 and rolled-back 0.2.0 daemon
then failed their startup donor check. The pipe-free candidate passed its
root layout check in the same boot (`69/68 -> 71/70 -> 69/68`), completed one
cooperative Prospero Win request, and then completed another three successive
requests in one bounded resident process. Each title reported `data_after=1`,
each transfer reported `donor_balance expected_two=1`. After the single
request and again after the three-request sequence, with the titles closed,
the root counters matched the pre-request baseline (`71/70` after a separate
shsrv restart). A fresh pipe write still
failed with `ENOMEM` after those requests. This validates the pipe-free
control path and balanced transfer on that firmware; long-duration operation
and the cause of pipe allocation failure remain unverified.
