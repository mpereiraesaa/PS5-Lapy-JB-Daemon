# Thread and stop field calibration

The next live-target adapter must prove that every thread is suspended before
moving any owned root reference. `signal_quiescence_probe` showed a stable
two-thread worker and a candidate `p_suspcount` field on the owned FW 12.02,
but did not independently count all threads.

Build the disposable probe with `--probe thread-stop-calibration` using
`tools/build_probe.py` and the installed SDK. It creates one child, grows it
from one to three threads through native `pthread_create`, then sends SIGSTOP
and SIGCONT. It reads only its child's kernel `proc` and thread-list objects.
It counts the live linked list at each phase, validates each thread's owner,
and requires `1→2→3→3→3` nodes. It also requires a unique aligned proc field
with `0→0→0→3→0`, a stable worker counter while stopped, resume progress,
and stable PID/proc identity.
The child is bounded and reaped on all paths. No title process is touched.

The candidate stop offset and linked-list layout are **runtime observations**,
not licensed firmware constants. The stock `p_numthreads` field did not show
a distinct `1→2→3` transition in the inspected first `0x900` bytes on 12.02;
the linked list provided the independent count. A future adapter must recheck
target identity, list membership and suspension count while the target is held,
and reject cycles, changed membership or ambiguous fields. This probe cannot
establish that Lapy may signal an unrelated title or that the title's filedesc
is private.

On the owned FW 12.02, build
`3b1d68bfc30e812ef058f3be1f1377b2ad93efc182ee5d5c7d8a8a0555e33f38`
(ELF SHA256 `0dc683397c49c825a7264f3c216798dc1e3da78acbdb055655a8f1d2dd9d30b7`)
completed with list counts `1,2,3,3,3`, one stop-field candidate at `0x3a0`,
stable worker ticks while stopped, resumed ticks afterward, stable process
identity and child reaped. The private clean `ps5log/1` stream SHA256 is
`6385147bddfdd4d56c781322fb3d7e491784df809de1d0f2a8aad1cafc13b0fe`.
This is evidence for the disposable child only; a live title still needs its
own stop/resume and identity verification.
