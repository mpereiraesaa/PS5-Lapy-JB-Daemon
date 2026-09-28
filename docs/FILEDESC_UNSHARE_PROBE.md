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
or claim to repair Lapy. It scans only the first 128 bytes of its own
`filedesc` for a unique aligned 16- or 32-bit field that changes 1→2 during
sharing, avoiding a fixed SDK structure offset. Multiple matches fail closed.

On a clean boot, under the shared `console:PS5` lease, run this **once** as a
standalone payload. It first requires its own `fd_refcnt` to be one. It creates
a child with native `rfork(RFPROC)`, which should share `filedesc`, and requires
the parent's count to become two. The child blocks on a pipe, with a 15-second
alarm as a bound. The parent then invokes native `rfork(RFFDG)` without
`RFPROC`, reads its new `p_fd`, and requires a different table with refcount
one while the child's old table also has refcount one. The parent releases and
reaps the child even when a check fails. No kernel pointer is logged.

The SDK and kstuff-lite headers disagree on the `filedesc` layout and the
counter's width. A success requires a unique candidate field, the observed
transitions and pointer identities to agree with the FreeBSD reference
behavior; it is not proof of the entire PS5 layout. A
failure or unexpected count stops this path for that firmware. Preserve the
server's stream and manifest together with the ELF manifest; do not infer a
successful result from a screenshot or an ELF build alone.

After the run, verify the four matching artifacts together:

```sh
python3 tools/analyze_filedesc_unshare.py STREAM.log SERVER.json \
  build/filedesc_unshare-probe/manifest.json \
  build/filedesc_unshare-probe/lapy_filedesc_unshare_probe.elf
```

The analyzer rejects stream gaps, unclean termination, identity/hash mismatch,
and any success claim that lacks the exact native 1→2→separate-1 transition.
It reports a cleanly logged syscall error as `supported: false`.

A successful self-test still leaves three requirements for the daemon: invoke
the unshare in the **target** process, hold that process and its threads stable
while changing the directory fields, and acquire/release vnode references
through native paths. Running `rfork(RFFDG)` in Lapy would isolate Lapy only.
The root-reference and symbol probes in `ROOT_REFERENCE_PROBE.md` address
different parts of the same transaction. Do not resume repeated legacy
escalations based on this probe's result alone.

On owned firmware 12.02, build
`080d47d7cff73fe2b803f9d68b7924f65a4d2ecf3dcc947639c61ceb7bd119b1`
(ELF SHA256 `e6acb6a1e13a380226e17e555ba30bb8ab4d00156efd3f614bfe38840525a941`)
completed this self-test. The private `ps5log/1` stream has a clean BYE and no
gaps; the identity-bound analyzer reported `supported: true`, a unique
four-byte candidate at `0x34`, and the `1→2→separate 1/1` transition. This
does not establish that Lapy can make the target process call `rfork(RFFDG)`
or that its directory slots are safe to edit afterward.
