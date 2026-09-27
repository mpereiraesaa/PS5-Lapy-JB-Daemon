# Native transport capability probe

This payload checks AF_UNIX/SOCK_SEQPACKET, SCM_RIGHTS, close-on-exec reception,
directory identity, and explicit descriptor close over 64 bounded transfers in
one process. It does not chroot, elevate a target, create children, modify title
files, or write kernel state. Normal SDK/loader startup is outside the probe.
Passing is only a transport gate, not proof of safe elevation, cross-sandbox
delivery, root/jail behavior, or balanced kernel cleanup across process exits.

```sh
PS5_PAYLOAD_SDK=/path/to/sdk/install python3 tools/build_probe.py \
    --logging-client /path/to/homebrew_ps5/projects/logging_server/client
```

Artifacts are ignored under `build/probe/`. The manifest binds the ELF SHA256
to a build ID embedded in structured runtime records. The logging header and
SDK inputs are hashed. Build does not deploy. No console addresses are compiled
in: the probe loads the normal ps5log dev.conf. It exits before testing if the
logging server is unavailable. No filesystem/USB logging mirror is enabled.

Before execution, read the coordination mailbox and acquire the global PS5
lease. Run from a known console state and send only this exact audited ELF to
the existing loader. Keep raw loader output and logging-server runs private.
Require a complete `ps5log/1` session with matching build ID, firmware,
`stage=complete error=0 completed=64 expected=64`, a complete bye record and no
sequence gaps. Record the SHA256 mapping beside the private evidence. Any
missing or failed result leaves the gate unproven; do not retry uncertain
execution automatically or infer success from the loader connection alone.
