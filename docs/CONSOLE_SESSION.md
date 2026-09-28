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
| 1 | `build/kernel_symbols-probe/lapy_kernel_symbols_probe.elf` | `33e14b050e51eab5613d0d447ebd2006e2aee19873d6e5ba72061b228133726d` | Whether native kernel names are exposed through `kldsym`; it never calls them. |
| 2 | `build/filedesc_unshare-probe/lapy_filedesc_unshare_probe.elf` | `e6acb6a1e13a380226e17e555ba30bb8ab4d00156efd3f614bfe38840525a941` | Whether native `rfork(RFFDG)` separates a deliberately shared table in the disposable probe. |
| 3 | Build `target-dirs` for the **actual live PID** | Per-PID manifest | Whether that target's original root/jail slots are null or equal before any escalation. |
| 4 | `build/root_refs-probe/lapy_root_refs_probe.elf` | `e6cb3ea4002bda4e1359ad3847d305b6776be5d20ddc690a732374c58a937c68` | Small root-vnode field changes across a bounded observation window. |
| 5 | `build/root_native_refs-probe/lapy_root_native_refs_probe.elf` | `5234a1754f84d4af0e27c227e1c26cf0659690586cc0dbcad07a80d69dbbc81e` | Native `open`/`close` calibration of root-vnode reference fields in a disposable payload. |

The corresponding build IDs are, respectively,
`a0b230010a01b8bb21b2c4e2e33ce849d3d5875247fc569713503d5cdde2d89c`,
`080d47d7cff73fe2b803f9d68b7924f65a4d2ecf3dcc947639c61ceb7bd119b1`,
`2f4a86fa1c819f021ed298d448bcb00d96d2daa275534343e7305d0a5ae949bf`,
and `beab8b6b87bacab5cdbc82f6299054b69d60057093dbcd28bf90d818729882ef`.
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
