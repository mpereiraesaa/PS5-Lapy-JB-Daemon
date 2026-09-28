# Native filedesc donor reference probe

The corrected daemon needs two owned system-root references when it replaces
both `fd_rdir` and `fd_jdir`, including a target whose original jail slot is
null. The old target roots must also be released. The native `fchdir` shuttle
can exchange an existing slot reference, but cannot create the extra reference
needed for a null jail slot. FreeBSD 11's
[`fdcopy`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/kern/kern_descrip.c)
explicitly `VREF`s each non-null copied cwd/root/jail slot, and its
[`fdescfree`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/kern/kern_descrip.c)
releases those references. Whether the owned PS5 follows that behavior needs a
native measurement.

Build the read-only probe using the installed SDK:

```sh
PS5_PAYLOAD_SDK=<installed-sdk> python3 tools/build_probe.py \
  --logging-client ../logging_server/client --probe donor-filedesc
```

It requires firmware 12.02 because the root-vnode observation fields at
`0x1bc` and `0x1c0`, and the filedesc reference hint at `0x34`, were measured
only there. It reads an initial root-vnode sample, creates one disposable child
with `rfork(RFPROC | RFFDG)`, checks that the child has a distinct filedesc
and the expected root/jail slots, samples while the child is alive, then lets
the child exit and reaps it before a final sample. The child is bounded by an
alarm and the parent has bounded waits and cleanup. Neither process edits
kernel memory or elevates another process. The probe does not publish kernel
addresses.

With the shared console lease and lab `ps5log/1` receiver, send the exact ELF
through `elfldr`, then validate its stream against the server/build manifests:

```sh
python3 tools/analyze_donor_filedesc.py STREAM.log SERVER.json \
  build/donor_filedesc-probe/manifest.json \
  build/donor_filedesc-probe/lapy_donor_filedesc_probe.elf
```

The analyzer requires one root reference from the child's root slot and a
second when its candidate cwd slot also points to the system root, with exact
return to baseline after child exit. If that is observed, it proves only that
native filedesc copying can supply disposable references in this process and
firmware. A corrected daemon would still need a safe ownership transfer from
donor slots to the target's old slots, private and retained filedesc objects,
native locking or equivalent full quiescence, a recoverable publication
transaction, credential isolation and repeated `/data`/exit/exec/rfork
validation. No pointer transfer is attempted here.

## Owned 12.02 result

Build `1a5e2ab00e6563f2cedf697024d7734bc41e7f2ee70203b866cbc07f40941646`
(ELF SHA256 `ffda5406646466484e5fbadda22951f87c8a84e17e4eecbdafab9f1c952eb869`)
passed the identity-bound analyzer with private ps5log/1 stream SHA256
`22d21cf1537b7fcdb50428e13504651133b785096d1d48d8b7c8665b2fc25cba`.
The root-vnode fields were `60/59` before `rfork`, `62/61` while the child was
alive, and `60/59` after it exited and was reaped. The child had a distinct
filedesc with observed refcount 1, system root and candidate cwd, and null
jail. This supports two native references acquired and released by the copied
filedesc. It does not establish that raw pointer swaps are synchronized or
safe in an active target.
