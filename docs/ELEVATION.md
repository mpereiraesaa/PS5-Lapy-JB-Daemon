# Repeated elevation: investigation and build status

This branch provides a source-pinned **legacy comparison build**, not the native
reference-lifetime fix. No runtime optimization or crash correction is claimed.
`make` refuses to select an unsafe backend implicitly. `make legacy` builds the
old elevation mechanism explicitly, for offline inspection. It does not deploy.

## Source and artifact identity

- Upstream Lapy: `434e6e7a867f85532b3c0f4d31f4f1c93bf57d8a`.
- Its tracked ELF SHA256:
  `e8230ac4597b8f0388e75d7515ad1a2e251c4589cc3b8d56a483ffae73627eed`.
- Pinned source dependency: [illusion0001/libhijacker at f1ac64a](https://github.com/illusion0001/libhijacker/tree/f1ac64ad97c1f3b2fbcb73a9e43832b5fbdeb23e).

Upstream does not include the archive required by its Makefile. Its shipped
headers differ from this dependency's headers, so this build consistently uses
the pinned dependency's own headers and source. It stages one compatibility
adjustment: remove `const` from the `kernel_base` declaration, since Lapy
initializes that variable from payload arguments. The dependency checkout is
never edited. Wrong revisions, tracked edits and extra files are rejected.

This is **not a bit-for-bit reconstruction** of the shipped ELF or proof of its
entire library provenance. Disassembly of the shipped `Hijacker::jailbreak`
does independently show direct `kernel_copyin` calls to `fd + 0x10` and
`fd + 0x18` with no native reference-acquisition call in that function. It also
contains an early UID check absent from the pinned source. This difference is
why a newly linked binary must not be presented as the original artifact.

## Build locally

Requirements: Python 3.10+, Git, the PS5 payload SDK, and compatible PS5 C++
runtime archives (`libc++.a`, `libc++abi.a`, `libunwind.a`). Host Linux runtime
archives are not substitutes.

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk/install
# Omit when these archives are already in the SDK's target/lib directory.
export PS5_CXXRT=/path/to/ps5-cxxrt
make check
make legacy
```

The local lab's SDK installation and existing debugger C++ runtime are usable;
neither is modified. A first build fetches the pinned dependency under `.deps/`.
Later builds work offline. Output is kept separately under `build/legacy/`:

- `lapy_jb_daemon_legacy.elf`: retains the unsafe elevation behavior.
- `manifest.json`: source revision/dirty flag, exact source/header hashes,
  SDK target-file hashes, runtime hashes, compiler version and ELF SHA256.
- `build.log`: exact compiler/linker commands and diagnostics.

The inherited top-level ELF is never overwritten. Generated files and dependency
checkouts are ignored. Dependency license: its `LICENSE.txt` contains GPLv2;
the original Lapy MIT notice remains intact. No new binary release is published.
The selected dependency has an upstream format warning in `dbg.cpp`; build logs
retain it. A successful cross-link establishes no firmware compatibility or
runtime safety.

## Native backend still required

The inspected SDK exposes kernel memory reads/writes and raw setters, not a
verified native credential/vnode transaction. FreeBSD header declarations do
not provide callable PS5 symbols. The inspected [kstuff-lite 12.02 table](https://github.com/blackbearreloaded/kstuff-lite/blob/4c2bcbc9b1f75ccb422413e84c2599755a0d2e16/prosper0gdb/offsets/12_02.h)
does not supply the required vnode/credential functions. This is a limitation
of the inspected paths, not proof that no usable implementation exists elsewhere.

Before replacing the legacy operation, implement and verify all of:

1. Resolve the requested PID to a live, retained process identity and coordinate
   with exit, exec and competing credential changes. Do not trust a cached PID.
2. Use the target process's correct execution context. Calling `seteuid` in the
   daemon changes the daemon, not the target. Validate the native credential
   copy/install path, auxiliary identity accounting and per-thread credentials.
3. Separate shared `filedesc` state with native semantics where needed; do not
   byte-copy locks or arrays. Account for the actual `rfork` sharing mode.
4. Acquire a native vnode reference for each new owning directory field,
   publish under the required locks, and release the old references correctly.
   Leave `fd_cdir` unchanged unless a specified behavior requires changing it;
   if changed, it has its own reference obligation.
5. Balance internal prison/identity references if those credentials change.
   Finish preparation before publishing state and unwind failures correctly.
6. Make repeated requests leave both privileges and owned-reference balances
   unchanged. Identical pointers alone do not prove reference ownership on a
   console previously modified by the old daemon.

No guessed offsets, raw counter increments, deliberately leaked old roots,
exit-only restoration, or automatic fallback to legacy writes belong in the
native backend. The [credential-copy commit](https://github.com/blackbearreloaded/kstuff-lite/commit/33ec81e5e086837f54644d519ed0a90b16d5c1f5)
still writes filesystem directory pointers directly and is insufficient alone.

### Limit of an `fchdir` reference shuttle

FreeBSD's native `fchdir` acquires a reference for its new `fd_cdir` and
releases the previous one. With an exclusive, quiescent `filedesc`, a valid
root directory FD in the **target**, and non-null original `fd_rdir` and
`fd_jdir`, moving the owned `fd_cdir` reference into each root slot between
native `fchdir` calls could in principle balance the old and new vnode refs.
This is a candidate transaction, not a tested PS5 backend. It still requires
verified target unsharing, all-thread quiescence, safe slot publication, checked
remote syscall results, and rollback or a safe forward-completion path.

It **cannot** cover a null original `fd_jdir` by pointer swaps and `fchdir`
alone. Those operations preserve the number of owning references across the
three directory slots; filling an initially null jail slot increases that
number by one. Swapping null into `fd_cdir` is not a valid workaround: the
FreeBSD `pwd_chdir` release path calls `vrele` on the previous cwd, and its
`vputx` implementation asserts the vnode is non-null. Such a case needs a
native reference-acquisition path (or a separately verified native root-change
operation). Until PS5 confirms the relevant behavior, the generic daemon must
reject that state rather than run the shuttle.

## Acceptance and evidence

Start native validation from a clean boot, with exclusive console coordination.
Use the lab's `projects/logging_server` and `ps5log/1` for structured runtime
evidence, not console filesystem or USB logs. Record artifact identity,
firmware, backend identity, process identity, request/result and balanced
reference operations. Do not publish addresses or private captures.

Test actual create/write/read/rename/unlink access in a dedicated `/data` test
directory; repeated requests on one process; independent process starts and
exits; the specific LoadExec path; and each intended rfork mode separately.
Exercise failure paths and concurrency. Host tests and clean compilation cannot
establish vnode ownership or kernel cleanup. Global vnode counters may change
because of unrelated activity, so before/after snapshots alone are insufficient.

Two reported crashes after repeated elevations motivate this investigation but
do not prove the cause or establish a safe number of launches. No console was
used to validate this branch.
