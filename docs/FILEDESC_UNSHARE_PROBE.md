# Native filedesc unshare capability probe

Build the disposable process probe with the same installed SDK used for the
other probes:

```sh
PS5_PAYLOAD_SDK=<installed-sdk> python3 tools/build_probe.py \
  --logging-client ../logging_server/client --probe filedesc-unshare
```

The builder writes an ignored ELF and identity manifest under
`build/filedesc_unshare-probe/`. The probe records only `ps5log/1` evidence.
It does not elevate credentials, write kernel memory, edit another process,
or claim to repair Lapy.

On a clean boot, under the shared `console:PS5` lease, run this **once** as a
standalone payload. It first requires its own `fd_refcnt` to be one. It creates
a child with native `rfork(RFPROC)`, which should share `filedesc`, and requires
the parent's count to become two. The child blocks on a pipe, with a 15-second
alarm as a bound. The parent then invokes native `rfork(RFFDG)` without
`RFPROC`, reads its new `p_fd`, and requires a different table with refcount
one while the child's old table also has refcount one. The parent releases and
reaps the child even when a check fails. No kernel pointer is logged.

The SDK `struct filedesc` gives the **candidate** `fd_refcnt` offset. A success
requires the observed transitions and pointer identities to agree with the
FreeBSD reference behavior; it is not proof of the entire PS5 layout. A
failure or unexpected count stops this path for that firmware. Preserve the
server's stream and manifest together with the ELF manifest; do not infer a
successful result from a screenshot or an ELF build alone.

A successful self-test still leaves three requirements for the daemon: invoke
the unshare in the **target** process, hold that process and its threads stable
while changing the directory fields, and acquire/release vnode references
through native paths. Running `rfork(RFFDG)` in Lapy would isolate Lapy only.
The root-reference and symbol probes in `ROOT_REFERENCE_PROBE.md` address
different parts of the same transaction. Do not resume repeated legacy
escalations based on this probe's result alone.
