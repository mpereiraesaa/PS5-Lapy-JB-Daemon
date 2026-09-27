# Observe the target's original root and jail slots

The old daemon overwrites both `fd_rdir` and `fd_jdir`, but prior 12.02 logs
did not record whether the launcher's or game's original jail slot was null.
That distinction determines whether a native `fchdir` reference shuttle could
even cover the process; a null slot needs an additional native acquisition.

With the Lapy daemon **stopped**, identify one live target PID by the normal
lab process inventory. Build a read-only ELF bound to that PID:

```sh
PS5_PAYLOAD_SDK=<installed-sdk> python3 tools/build_probe.py \
  --logging-client ../logging_server/client --probe target-dirs \
  --target-pid <live-pid>
```

The ELF, build log and identity manifest go under
`build/target_dirs-probe/pid-<live-pid>/`. The bundled PID 4242 build is only
an offline compiler check; it is **not** a console target. Use the shared
`console:PS5` lease and the lab's ps5log/1 server. Run the probe once before
elevating the target. It only reads the target's filedesc and the SDK's
per-firmware root/jail offsets twice, 10 ms apart. It reports nullness,
equality and optional system-root identity as booleans, with no kernel
addresses, writes, descriptor transfers or process suspension. If the PID
disappears or a slot changes between reads, it reports failure.

Verify the matching stream, server manifest, build manifest and ELF:

```sh
python3 tools/analyze_target_dirs.py STREAM.log SERVER.json \
  build/target_dirs-probe/pid-<live-pid>/manifest.json \
  build/target_dirs-probe/pid-<live-pid>/lapy_target_dirs_probe.elf
```

The analyzer rejects incomplete logs, identity/hash mismatch and impossible
flag combinations. A successful observation establishes only what the two
snapshots showed. The probe does not retain the process, prove the SDK layout
on another firmware, identify a vnode reference count, or fix Lapy. If the
target was already elevated by the old daemon, its original slots have been
lost; discard that run for this question.
