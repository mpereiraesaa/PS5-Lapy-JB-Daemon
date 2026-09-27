# Native VFS availability gate

Build using `tools/build_probe.py --probe vfs` with the same SDK and
`--logging-client` arguments as the other probes. Artifacts go to ignored
`build/vfs-probe/`. Acquire the console lease before sending the exact ELF.

The payload opens its current working directory and current root. It calls
native fchdir(root), then chroot("."), verifies that the new root names the
same directory and restores its prior working directory. It does not change
credentials, write kernel fields, create processes or touch another title.
This changes native filesystem state in the payload process, even though it
selects the same effective root; SDK/loader startup is outside the probe.

Require a matching build/firmware ps5log session, both operation records,
`stage=complete error=0 restore_error=0 completed=1 expected=1`, clean BYE and
no gaps. This is a syscall availability gate. It does not prove cross-sandbox
root adoption, preservation of a game's jail directory, filedesc isolation,
vnode refcounts or lifecycle safety. Unsupported syscalls must stop this route;
never substitute direct root/jail pointer writes.

## Corrected observation on 12.02

Build `fc4cefb05785d1657dffe9ec0103cbfcde1a2af92c0367383f81dc0edf7fe0e7`,
ELF SHA256 `f9341d69b351be6681ce8fe3ac3678a462d89319403bdaf5160816f75b5f7c37`,
reported success, but that conclusion was invalid: the SDK's libc wrappers
return the raw syscall result without interpreting the FreeBSD carry flag.
Checking only for a negative return value accepts positive kernel errors as
success. Unchanged root identity cannot detect this when selecting the same
root. The session ended cleanly; its private log SHA256 was:
`7927c4db671c5195cdce77eebcea762721744da461f843be01a8d4331f576895`.
This artifact is **not evidence of successful chroot or fchdir**.

The current probes use `native_vfs_syscall.h`, which captures the carry flag
and returns a positive errno. It never relies on stale libc errno for those
two calls. The SDK's source `libc/syscalls.c` confirms the wrapper behavior.

## Different-root gate

`--probe cross-root` builds under `build/cross_root-probe/`. It selects /data as
the payload's temporary root, verifies directory identity and requires jaildir
to equal that sandbox root, then adopts the saved original root using native
fchdir/chroot. It requires preservation of the sandbox jaildir and checks
/data identity afterward. It restores effective root and cwd on failures after
a successful root change. It never overwrites jaildir; no files are created.
This is a controlled chroot sandbox, not a Sony title sandbox.

The corrected checked-call build
`36525bf6b71157a6137cc11d2cf1988cc9cf5e0f2177c563bdfcab3ed54c9c88`,
ELF `8841b063dbf2364d63740252fe010e9365e8609e9a1ba3b2628e10f32e5b84e9`,
returned **EPERM (1)** at chroot(/data), before any root change. The log ended
with clean BYE and no gaps, SHA256:
`dd0602b84a34298394ab43e59ab6858f87adbfb9a0cbbdfc12f0d1c8616c9aaa`.

The route is not yet usable with the probe's current credentials. Next verify
the caller's native identity and Sony privilege prerequisites. SDK startup
changes selected capability bytes; full chroot privileges cannot be inferred
from successful loading, /data visibility or seteuid(current). Do not substitute
raw vnode writes or claim the lifetime problem is fixed.

The prerequisites diagnostic (build
`4ce53bde24a87b877ee59eed0de1d8665e5ab5f9163e05e7e6a669643be001f8`, ELF
`2108cabac22a1aa32d6efe8f906402032f902458a92eb4cbc3e4a3f2eeef65ce`)
observed effective UID 0, real UID nonzero, non-system Sony authority, incomplete
Sony capabilities, and attribute bit 0x80 set. fchdir(-1) correctly returned
EBADF, followed by chroot EPERM. Both queried chroot/superuser sysctls returned
ENOENT, so their policy values remain unknown. The clean private ps5log SHA256
is `e5dbe16b7fe3a86ea6d7134bcd4a306107ea61eb4d598275ed63b35d39034249`.
These observations motivate testing Sony privileges on a natively cloned
credential; they do not identify the exact permission check that rejects chroot.
