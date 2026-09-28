# Pre-entry title crash log snapshot

Prospero Win `PPSA99995` mounted successfully on FW 12.02, then entered an
exception-stop and exited about one second after launch. Its own `ps5log/1`
stream and `/download0/etahen_jailbreak` request never appeared. The old Lapy
daemon had already been identified by three in-memory signatures and stopped.
ShadowMountPlus reported `0x00088102` and explicitly classified the crash as
before KStuff's delayed auto-pause, but did not include an exception reason.

The first disposable build called Sony's diagnostic text APIs directly;
both returned `0x8001ffff`, with no lines, in a complete `ps5log/1` stream.
The revised one-shot payload first clones its **own** credential with native
`seteuid(geteuid())`, requires a new credential pointer with unchanged fields,
temporarily applies the coredump authid/caps used by ShadowMountPlus, reads
the SDK and private diagnostic text snapshots, and restores its original
authid/caps before exit. It does not modify a title's credentials or filedesc.
It filters lines mentioning this title, the
two observed PIDs, exceptions, faults, or the runtime loader, and sends at
most 80 bounded lines to the lab's private `ps5log/1` receiver. It neither
launches a title nor modifies another process. Build with
`tools/build_probe.py --probe preentry-log` and the installed SDK/logging
client. Preserve its ELF manifest with the private stream. The snapshot may
not retain prior crash lines; a zero-match result does not exonerate any
component. No raw diagnostic log or personal content belongs in the PR.

The revised FW 12.02 hardware run completed with a private credential and
restored its original authid/caps. Both APIs returned success and 131072 bytes
of text, but the bounded filter matched zero lines. The complete private
`ps5log/1` stream is
`20260928T083711364Z_LAPYCRASH_lapy-preentry-log-probe_0x1f71b93178e5`;
its tested build ID is
`06bef9db45155545d80fe1439fd94975db45b83060ff48982899c82cfbaf9f38`.
The crash cause remains undetermined. A later `PPSA99994` native Hello World
gate proved that Lapy can still elevate another title to read and write
`/data`; that result does not explain Prospero Win's earlier launch exit.
