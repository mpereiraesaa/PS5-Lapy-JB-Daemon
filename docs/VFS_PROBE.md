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

## Observed on 12.02

Build `fc4cefb05785d1657dffe9ec0103cbfcde1a2af92c0367383f81dc0edf7fe0e7`,
ELF SHA256 `f9341d69b351be6681ce8fe3ac3678a462d89319403bdaf5160816f75b5f7c37`,
passed the existing-root operation and cwd restoration. The ps5log session
ended cleanly with BYE and no gaps; private log SHA256:
`7927c4db671c5195cdce77eebcea762721744da461f843be01a8d4331f576895`.
The next necessary gate is adoption of a different root, preserving an existing
jail directory, followed by access under /data. This observation proves neither.
