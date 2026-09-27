# Native Unix identity prerequisite

The observed loader process has effective UID 0 but a nonzero real UID.
`--probe cross-root --root-identity` explicitly selects native setgid(0) and
setuid(0) with checked syscall carry flags, before the optional Sony scope.
It verifies real/effective UID and GID plus saved UID are zero. No UID, group,
prison or reference fields are written directly. Identity accounting and
credential replacement belong to the native kernel paths.

This option is for a disposable payload process: the native Unix identity is
retained until process exit, including on a later probe failure. Sony authority
and capability fields, if explicitly selected, are separately scoped and
restored. Root/cwd restoration follows the cross-root probe's normal contract.
No other title or process is changed and no children or files are created.

Build with the normal SDK and logging-client arguments plus
`--probe cross-root --root-identity --sony-privileges`. Acquire the console
lease before deployment. Require a complete matching ps5log record including
native identity readback and the final result; compilation is not validation.
This tests a prerequisite and does not prove remote elevation or lifecycle
safety. No fallback to raw identity/root writes is permitted.

`--cwd-root` retains the original root as the working directory across the
temporary chroot, then adopts it with chroot("."). It opens no root/cwd
descriptors of its own and restores the prior cwd by saved path. It does not
prove the loader inherited no other directory descriptors. The prerequisites
diagnostic compares the current prison pointer to the SDK's prison0 symbol,
without changing or publishing either pointer.

## Observations on 12.02

Native Unix identity readback passed, but chroot returned EPERM with the
directory-descriptor variant (build
`3e8e296862f1509aa7503f269b113d5144fb5511bbc3e56066d25bcd20c06676`, ELF
`56345dad96731d7d2d2fcdce3f984baa39e64c63e7cc435a7bd0f06736e28b6e`, log SHA256
`9f72841968ab31e653f39c825cdbca0c84055c89b9a5a3f453198be621a11fb2`).

The cwd variant also returned EPERM, with prison0 already selected and native
UID/GID/saved UID 0 plus full Sony caps/system authority verified (build
`4a583dfb09ffd0739ca95ee8681ce8d2ad25d88da4dd12ca8de9592ca492184e`, ELF
`78e4f05ace0c696ea039cd4fe369ccbc5a84ecd6aedf3025fcc13a94425e62f9`, log SHA256
`851b1a1eafccd62cddc123166ffeb15ca458859ed166b147802ddc214b2d6f6d`).
Both stopped before root adoption, restored Sony state, and ended with clean
BYE/no gaps. The VFS route remains unproven despite these prerequisites.

## Read-only syscall-table classification

`--probe sysent` reads eight data-table entries on 12.02 only. It uses the
[pinned kstuff-lite table](https://github.com/blackbearreloaded/kstuff-lite/blob/33ec81e5e086837f54644d519ed0a90b16d5c1f5/prosper0gdb/offsets/12_02.h),
checks the independent SDK allproc anchor, validates argument counts for four
control calls, and compares handler identities without publishing addresses.
It never reads executable kernel memory or invokes a kernel pointer.

Build `b54d5e534c309d0a603e5b13214a466a7509f43218db416b294e3a2472d3f8bc`, ELF
`ee9679e2cd1b6a95a72ca00c7dda5659fdf8fab8eee85c7fb7d05550efb7f1f3`, passed
the controls. chroot has one argument and a handler distinct from slots
0, 8, 11, fchdir and seteuid. Thus the generic missing-syscall-handler hypothesis
is not supported. A distinct handler does not prove a working implementation
or explain EPERM. Clean private log SHA256:
`61f7ded3fb89778f0230310a13bb4aa1ecbaaa1ae43680081fc8ca6387bf5ef7`.

## Descriptor and active-dispatch follow-up

The fd inventory uses the larger available value from getdtablesize and
RLIMIT_NOFILE, rejects bounds over 32768, and fstats each descriptor without
closing inherited descriptors. The observed bounds were 12555 and 13952.
An earlier 4096 cap stopped the probe before chroot; it was not a syscall
failure. With the corrected bound, 13952 slots contained eight open descriptors
and **zero directories**, but chroot still returned EPERM. Build
`c643c1d3f0867645c92e693e4e72da65fb8388b8c18d2b99a9b695a6a02611d6`, ELF
`de5de0e57aed0af515a79b580b3d0de6c8b15cf8e7f93d874267eab46b9cff68`, clean log
`d0b666d0ee887a6412ca16dadd89e8afea41ae74b45e8a5c8205f22dfa6642b5`.
This does not support the inherited-directory hypothesis within those bounds.

The syscall classifier now reads the current process's actual p_sysent using
the pinned 12.02 offset. It validates vector size and pointer form, understands
the documented kstuff 0xdeb7 table marker, and compares active chroot against
both stock PS5 and PS4 entries. It observed the **PS5 vector and stock PS5
chroot handler**, without the marker. Thus the compatibility-dispatch hypothesis
does not explain this payload's failure. Build
`9db1aa2d8bcb42d7fa8603761b58a0a7d1990b74467187a8c738bf73cc208e35`, ELF
`1a109c0fe5929c5b08777e70d59834d72d98278e945b6857bdac583704b12cea`, clean log
`dac9c3cd737ce4f1eaff190107f7fe9c80da9d433cbc611056d704e7abafaca8`.

Further progress on chroot requires identifying its actual rejection path,
not repeating the same credential combinations. Pinned prosper0gdb offers
kernel tracing/calls but is not an ordinary SDK API: its setup changes IDT/TSS
state across CPUs and cannot be assumed compatible with installed hooks.
No such instrumentation has been deployed by these probes. A kernel tracing
backend needs a separate integration/cleanup audit before execution.
