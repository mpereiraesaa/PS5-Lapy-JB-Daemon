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

## Firmware 12.02 observation

The atomic-receiver probe built as
`cfcd84af0cc4580f1069e0d610e60d85181c7978c7c48aaa7a89bcec557e3c17`
(ELF SHA256 `8779ddfe33e6beef27b26abbed05f9ecbf7209c6feefc8e8a167a2e8fbd7621b`)
ended at `receive_cloexec_missing`, errno 45, zero completed cycles, with a
clean ps5log BYE and no sequence gaps. The transfer succeeded but F_GETFD did
not report FD_CLOEXEC despite MSG_CMSG_CLOEXEC. The receiver closed the imported
descriptor. This is a compatibility finding, not a successful transport gate.

`--exclusive-receiver` builds a separate, explicitly selected probe using
recvmsg followed by F_SETFD and F_GETFD verification. This probe contains no
fork, exec, new threads or asynchronous signal handlers; ps5log is synchronous.
The mode is included in build identity and runtime telemetry. There is no
automatic fallback from the atomic path. A future daemon may use this API only
while it excludes fork/exec and descriptor-table mutation by all other threads
and table sharers. This probe does not implement or validate target quiescence.

The exclusive-receiver build
`11deb232482435a42ab49ff91db1b7accd5445b42446f21e36cc22488c38ed90`
(ELF SHA256 `cf5a40eb04417f3f4f065dc032d049912ee2f99873a839b4a87a20b0af345bb6`)
completed 64/64 cycles on 12.02 with `stage=complete error=0`, clean BYE and no
sequence gaps. The private ps5log record's SHA256 is
`e477c937b02ba8c93c0a6adaa26715bb5e5d4e162f3012113d11853d92c71221`.
This establishes same-process transport compatibility only, not cross-sandbox
access or correctness of elevation, exec, process exit, or vnode references.
