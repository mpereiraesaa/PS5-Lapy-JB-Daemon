# Owned-root Lapy daemon

The corrected backend is `source/owned_root_daemon.c`. On firmware 12.02 it
replaces the legacy direct root-pointer overwrite with a transfer of **two
native vnode references**. Two disposable `rfork(RFPROC|RFFDG)` children each
inherit a system-root reference. While the requested title is stopped, Lapy
moves those references into its `fd_rdir` and `fd_jdir` slots, and moves the
title's two old root/jail references into the donor filedescs. Native donor
exit releases the old references. The title owns the system-root references
until its own exit or exec cleanup releases them.

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
controlled tests. Both variants reject unsupported firmware at startup; the
kernel structure checks and root use/hold counter offsets have been calibrated
on **FW 12.02 only**. This is not yet a multi-firmware release. It does not
silently fall back to `Hijacker::jailbreak(true)`.

Build with the installed SDK and the lab's `ps5log/1` client:

```sh
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make owned-service
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make owned-one-shot
```

The resident ELF is
`build/owned_root_daemon-fw1202-service/lapy_owned_root_daemon.elf`. The
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

The outstanding work for other firmware is to calibrate and validate its
filedesc, thread, credential and vnode-counter layout before removing the
12.02 gate. Other homebrews must adopt the cooperative `seteuid` call, or a
future daemon must find a separately validated native target-clone method.
The payload-side `PT_READ_I` and `PT_IO` attempts did not return usable target
code bytes on this firmware, so they are not used for target cloning here.
