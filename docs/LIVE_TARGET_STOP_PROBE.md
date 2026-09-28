# Live title stop observer

This FW 12.02 only, one-shot probe watches for a fresh `PPSA99995` Lapy
request for up to 60 seconds. It reads the requester's PID and validates its
kernel process identity, then sends `SIGSTOP`, counts all linked threads and
checks the observed suspension field against that count twice. It also checks
that the target `filedesc` is private (`fd_refcnt == 1`). It resumes the title
with `SIGCONT` and removes the request marker in every exit path after a
request is found, so the caller can continue. It never elevates or writes
kernel memory; `/data` access will still fail after its acknowledgement.

Build with `tools/build_probe.py --probe live-target-stop` and the installed
SDK and logging client. Run only while the actual target title is available,
under the lab's `console:PS5` lease, and keep the exact ELF identity alongside
the private `ps5log/1` stream. A clean result establishes only that this
particular title was held and resumed under the observed conditions. It does
not transfer vnode references or clone target credentials. Any failed signal,
unstable identity/list, missing request or shared `filedesc` is a failed gate;
there is no elevation fallback.

This is a diagnostic probe, not a production authorization path. A PID read
from the marker cannot be retained across a userland `kill(pid, SIGSTOP)`;
exit and PID reuse in that window remain possible. A production backend needs
a retained target identity or a cooperative target-side stop protocol before
using this operation. The first owned-console attempt did not reach this path:
launching `PPSA99995` returned `0x80940033`, no request appeared, and the probe
completed a clean 60-second timeout without signaling any process. It therefore
provides no evidence yet about whether an unrelated title can be stopped and
resumed by Lapy.
