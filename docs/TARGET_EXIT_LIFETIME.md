# Target exit-lifetime reproduction

`owned_root_daemon.c` keeps raw `proc`, `filedesc`, and `ucred` addresses after
it ptrace-stops a requested title. It then creates and stops two donor
processes before using those addresses. A title can be killed by its launcher
during that interval.

The `live-target-ptrace --exit-lifetime` probe reproduces the lifetime
transition without writing through a stale address. It attaches to a
disposable title, verifies its private filedesc, delivers `SIGKILL`, and reads
only the retained `proc` fields until it observes the original PID with
`p_fd == NULL`. That state proves that process identity alone does not keep the
cached filedesc alive. The probe then reaps the title and exits.

Build the exact artifacts under WSL:

```sh
python3 tools/build_probe.py --probe live-target-ptrace --exit-lifetime \
  --target-title PPSA99999 --sdk /opt/ps5-payload-sdk \
  --logging-client /path/to/logging_server/client
python3 tools/build_exit_lifetime_target.py \
  --boilerplate /path/to/ps5-native-app-boilerplate
```

For an attended hardware run, first acquire the shared console lock and start
the WSL-only receiver. Deploy only the generated PPSA99999 `eboot.bin`, start:

```sh
python3 tools/run_exit_lifetime_probe.py 192.168.4.30 --title PPSA99999
```

and launch PPSA99999 when requested. A valid reproduction requires the exact
build ID plus `retained_proc=1`, `fd_cleared=1`, a reaped target, a complete
`BYE`, and no panic in the captured klog window. Restore the previous title
bytes after the single run.

This probe establishes the stale-address precondition; it intentionally does
not perform the unsafe root or credential write.
