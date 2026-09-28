# Next owned PS5 session: reference-lifetime gates

These are diagnostics for firmware 12.02, **not** a corrected Lapy daemon.
Start from a clean boot, read the lab coordination mailbox, claim the global
`console:PS5` lease, and run the lab's `projects/logging_server` ps5log/1
receiver. Preserve each stream with its server and ELF manifests. Do not use
USB or console filesystem logs as evidence. Stop on an unexpected reboot,
incomplete stream or artifact mismatch.

All paths below are relative to this project. The ignored build artifacts in
this workspace were cross-compiled with the installed PS5 SDK. Before running
one, compare its SHA256 to the listed value; a rebuild changes its identity.

| Order | Probe | Local ELF SHA256 | What it can establish |
| --- | --- | --- | --- |
| 1 | `build/kernel_symbols-probe/lapy_kernel_symbols_probe.elf` | `0cf6a5ab422e23b71b01841168b6d49a1ee31e2029669a91778a4129061e2aa1` | Whether native kernel names are exposed through `kldsym` and the caller's credential context; it never calls the names. |
| 2 | `build/filedesc_unshare-probe/lapy_filedesc_unshare_probe.elf` | `e6acb6a1e13a380226e17e555ba30bb8ab4d00156efd3f614bfe38840525a941` | Whether native `rfork(RFFDG)` separates a deliberately shared table in the disposable probe. |
| 3 | Build `target-dirs` for the **actual live PID** | Per-PID manifest | Whether that target's original root/jail slots are null or equal before any escalation. |
| 4 | `build/root_refs-probe/lapy_root_refs_probe.elf` | `e6cb3ea4002bda4e1359ad3847d305b6776be5d20ddc690a732374c58a937c68` | Small root-vnode field changes across a bounded observation window. |
| 5 | `build/root_native_refs-probe/lapy_root_native_refs_probe.elf` | `5234a1754f84d4af0e27c227e1c26cf0659690586cc0dbcad07a80d69dbbc81e` | Native `open`/`close` calibration of root-vnode reference fields in a disposable payload. |
| 6 | `build/cross_process_directory-probe/lapy_cross_process_directory_probe.elf` | `cabf8b8a700bd70e049b914fd6b81b19f49c4c3a31c099a800a5798358e3328c` | Native root FD transfer between disposable processes and use after sender close. |
| 7 | `build/request_dirs-probe/lapy_request_dirs_probe.elf` | See current build manifest | One-shot observation of a new `PPSA99995` request before elevation; it acknowledges without elevation. |
| 8 | `build/donor_filedesc-probe/lapy_donor_filedesc_probe.elf` | See current build manifest | Native donor filedesc copy and release, measured through root-vnode fields; no pointer writes. |
| 9 | `build/null_jail_transfer-probe/lapy_null_jail_transfer_probe.elf` | See current build manifest | Controlled donor reference transfer into and out of a disposable payload's null jail slot; writes two filedesc slots. |
| 10 | `build/old_root_release-probe/lapy_old_root_release_probe.elf` | See current build manifest | Controlled release of a displaced `/data` root through native donor exit; writes verified filedesc slots. |

The corresponding build IDs are, respectively,
`8fbf542ecb3c9417750d52a86ba74793c3d6833b22f0bad21c30d5cf56d0dc38`,
`080d47d7cff73fe2b803f9d68b7924f65a4d2ecf3dcc947639c61ceb7bd119b1`,
`2f4a86fa1c819f021ed298d448bcb00d96d2daa275534343e7305d0a5ae949bf`,
`beab8b6b87bacab5cdbc82f6299054b69d60057093dbcd28bf90d818729882ef`,
and `758960f80b3dfd7beecda52414a54e4e1870c10590584b6e6a5ec36d8aa28d7f`.
For step 3, follow `TARGET_DIRECTORY_PROBE.md`; the offline PID 4242 ELF is
only a compiler check and must never be mistaken for the live target build.

Run the first two probes without legacy elevation. Step 3 must precede any
Lapy request by that process, because the old daemon destroys evidence of its
original slots. If its jail slot is null, the `fchdir` pointer-transfer idea
cannot populate it without an additional native vnode acquisition. If it is
non-null, the idea remains conditional on safe target FD delivery, private
filedesc ownership, quiescence, checked syscalls and publication.

Step 4 is optional for distinguishing the missing-reference hypothesis. If
used, follow `ROOT_REFERENCE_PROBE.md`: a 120-second window, at most a few
ordinary escalation/close events from a clean boot, and no stress loop. Its
host analyzer checks stream completeness; correlation of a field with exits
is evidence, not identification of a PS5 vnode counter or permission to write
one. Continue the native adapter only after these observations have been
reviewed. Full acceptance still requires balanced native references and
repeated real `/data` operations through exit, LoadExec and intended rfork
modes. None of these probes alone satisfies that acceptance gate.

Step 5 runs independently without elevation and has already completed on
12.02. Its artifact-bound analyzer requires each of four native opens to add
one to both observed root-vnode fields and each close to remove one. It does
not grant permission to edit those fields directly or solve transfer of a
system-root descriptor into a sandboxed target.

Step 6 has also completed on 12.02. Its child closes the inherited root FD
before receiving a new one, then verifies directory identity and use after
the parent closes its copy. This tests cross-process transport in the same
root context, not delivery into a sandboxed game or launcher.

Step 8 completed on owned 12.02 without a title launch or legacy elevation.
Follow `DONOR_FILEDESC_PROBE.md`: the private filedesc child acquired two
system-root references natively and released both at exit, with a complete
identity-bound ps5log/1 record. This is a prerequisite for a reference-donor
design, not proof that a target can be changed safely.

Step 9 completed on owned 12.02. Follow `DONOR_NULL_JAIL_TRANSFER.md`: it
wrote only verified directory slots in private disposable processes. Native
root fields returned exactly to baseline after both donors exited. It did
not elevate or target a game or launcher, and does not establish active-target
quiescence or rollback.

Step 10 completed on owned 12.02, including 40 consecutive balanced runs.
It tests the old-root release half of the ownership transaction using a
native `/data` cwd reference. Follow `DONOR_OLD_ROOT_RELEASE.md`. Its
firmware-specific candidate cwd layout and disposable-process result cannot
be treated as active-target safety evidence.

Step 7 was built and run once on 12.02. The title launcher did not pass the
lab supervisor's service preflight because `shsrv` was unavailable; the
observer correctly timed out with a complete, identity-bound ps5log/1 stream
and did not claim a target observation. When the service is healthy, repeat
the one-shot procedure in `TARGET_DIRECTORY_PROBE.md` with the old daemon
stopped and the exact lab title, then close it. Do not treat the timeout as
evidence about the target's root or jail slots.
