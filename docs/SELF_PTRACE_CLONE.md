# Payload-side ptrace credential clone probe

The host-driven remote clone probe checks the target-side native syscall, but
production Lapy cannot assume an attached host debugger. This FW 12.02-only
one-shot probe tests whether an elevated payload can perform the same operation
itself with native `ptrace`. It creates a disposable child with
`rfork(RFPROC|RFFDG)`, obtains a **private parent credential** through native
`seteuid(geteuid())`, temporarily selects libhijacker's documented ptrace
Sony authority on that private credential, and attaches only to its child.
The probe verifies the child's `syscall; int3` gadget through `PT_READ_I`, saves
its registers, single-steps native `seteuid` in the child, restores every
register, checks that the child's `ucred` pointer changed while UID, prison
and Sony fields remained equal, detaches, restores
the parent's original Sony authority, and lets the child exit normally.
It changes no root/jail field or credential pointer directly and does not touch
any homebrew title.

Build offline with the installed SDK and logging client:

```sh
python3 tools/build_probe.py --probe self-ptrace-clone \
  --sdk /path/to/ps5-payload-sdk/install \
  --logging-client ../logging_server/client
```

Before the next attended console session, compare the current generated build
manifest and ELF with the recorded identity in this branch. The final prepared
build ID and ELF SHA-256 are recorded below; rebuilding changes the ID. With
`console:PS5` held and the lab `ps5log/1` receiver running, send only
`build/self_ptrace_clone-probe/lapy_self_ptrace_clone_probe.elf` to elfldr once.
No ps5debug-NG host debugger or game should be active for this test. The
payload emits a complete `LAPYPTC` stream with stage, errno, clone, register
restoration, detach, parent authority restoration and child reaping. A
`probe_held` event means ptrace state is uncertain and the process deliberately
stays alive for attended repair; do not kill it reflexively.

Prepared build ID:
`460439d10f5c5567090feba4cd71ff913d6b37ef3d3640431541c109b6245d69`;
ELF SHA-256:
`83e1b92ee612d52e6bd08108c267241a528a1be52d91e98a4b24a599d1a7014f`.

If `PT_ATTACH` fails, the result classifies payload-side ptrace as unavailable
under the tested authority and firmware, without attempting a fallback kernel
write. If it passes, it supplies a candidate target-side native credential
clone path for the daemon. Real-title use still requires stable target identity,
all-thread suspension, a private target filedesc, confirmed per-thread
credential propagation, the two-root transaction's console validation and
repeated exit/exec/rfork tests. This probe alone does not prove unlimited
homebrew elevation.
