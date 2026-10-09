# Target exit-lifetime reproduction

The old owned-root daemon read a target's raw `proc`, `filedesc`, and `ucred`
addresses before `PT_ATTACH`. A title that exited between those lookups and
the later `kernel_copyout` calls could leave the daemon dereferencing released
kernel objects. The failure is timing-dependent: released memory can remain
mapped long enough to return plausible or zeroed data, be reused, or fault the
kernel.

## Reproduce the stale read

Build a disposable title that writes the owned-daemon request and exits after
500 ms, plus a bounded daemon that waits two seconds after capturing the raw
target pointers and before dereferencing them:

```sh
python3 tools/build_exit_lifetime_target.py \
  --boilerplate /path/to/ps5-native-app-boilerplate --owned-race
python3 tools/build_owned_daemon.py \
  --sdk /opt/ps5-payload-sdk \
  --logging-client /path/to/logging_server/client \
  --service --max-requests 1 --title PPSA89012 \
  --result-file /data/lapy-owned-race.log \
  --target-snapshot-delay-us 2000000
```

Deploy the generated signed title as a backed-up disposable title, start the
daemon, wait for `daemon_ready`, and launch the title. The unfixed daemon on FW
12.70 produced this marker:

```text
target_snapshot_delay ... proc_current=1 fd_current=0 ucred_current=0 delay_us=2000000
target_state ... fd_refs=0 cred_refs=0 ...
request_result ... stage=target_preflight error=16
```

The exact unfixed daemon had build ID
`347647408d4d3a18906841661584d52fea418a73600199de85455ee30a590b19`
and SHA-256
`e5f19eea52c7ce4194722f3e045582bfa30d28853ef9219ca5f9e727b4ec1e9d`.
The signed target SHA-256 was
`ebc4315b307697a12c9e361817f9c96bdce07e8d1037be23b547342ed1d98c74`.

This run did not panic: the freed objects were still readable and returned
zero reference counts. It nevertheless directly confirms the stale-pointer
bug that can explain intermittent panics when the same memory is unmapped or
reused.

## Fix and validation

The daemon now obtains ptrace authority, attaches, observes `WIFSTOPPED`, and
only then takes and verifies two stable target snapshots. Credential reads and
all later kernel-pointer use happen while that stop is held. A target that
exits before the stop is observed is handled as a vanished request without
consulting an uninitialized or stale identity.

The same FW 12.70 title and two-second delay against the fixed build produced:

```text
target_snapshot_delay ... proc_current=1 fd_current=1 ucred_current=1 delay_us=2000000
target_state ... fd_refs=1 cred_refs=2 threads=1 suspended=1 ...
credentials_applied ...
roots_committed ...
donor_balance ... expected_two=1
request_result ... stage=complete error=0 ... detached=1 donors_reaped=1
```

The fixed diagnostic daemon had build ID
`7b856069da2d1b10601f9c3756e8d040df855d65c0018da439f2cb4b81324094`
and SHA-256
`a5210f810a13725293cd3efb434950e2a03fa2651aa4da0bb141ee8638117e24`.
The console remained reachable on FTP, klog, and elfldr after the test, the
active title sandbox disappeared, and the original title was restored with
the same retrieved SHA-256. No kernel panic occurred. The disposable app's
known user-process `SIGSYS` during exit appeared in both unfixed and fixed
klogs and is separate from the daemon lifetime bug.

## Ptrace-stop calibration

The read-only `live-target-ptrace --exit-lifetime` probe was also used to test
the originally suspected post-attach donor-preparation interval. An external
`SIGKILL` stayed pending while the title was ptrace-stopped and its filedesc
remained current. Once resumed, the title was reaped before an intermediate
`p_fd == NULL` state could be sampled. That result refuted the post-attach
theory and narrowed the bug to the daemon's pre-attach snapshot.
