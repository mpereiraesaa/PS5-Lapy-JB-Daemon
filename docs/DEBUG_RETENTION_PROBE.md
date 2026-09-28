# SceShellCore debugger retention probe

`ps5debug-ng` is active on the owned console. Its server runs inside
SceShellCore, and its `PT_ATTACH` path may provide the retained target identity
and all-thread stop needed before a corrected Lapy transaction. This probe
tests that path only on a disposable, two-thread child. It does not target a
game, change credentials, or write kernel memory.

Build with `tools/build_probe.py --probe debug-retention` using the installed
SDK. The ELF logs a child PID over `ps5log/1`, keeps it alive for 15 seconds,
then releases and reaps it. A host coordinator under the `console:PS5` lease
can attach that PID through the existing ps5debug-ng service, stop it,
resume and detach. `DEBUG_GET_THREAD_LIST` returned an error on the first
disposable test, so the probe does not rely on it. The parent independently
checks that the worker counter stops for at least three consecutive 100 ms
samples and then advances again. Keep the exact ELF manifest and private
stream with the coordinator result. A successful attach to this child is only
a prerequisite; a real title may have different AppContext behavior and must
be tested separately before any root transfer.

The owned FW 12.02 run used build
`64b91b23913e9f32ea34f71b41b4205f21910ddaa9dca188b4e2b57e093a0ab7`
(ELF SHA256 `36f57ac7f1a1695186d1bbbe9d3b33150a1159dd60056288662e3e11e4336b8d`).
The host client reported attach, STOP, RESUME and detach success. The child's
parent independently observed a worker plateau during the one-second STOP,
progress after RESUME and normal reap; the complete private `ps5log/1` stream
SHA256 is `49e25b3aaf9cc566eabe3837d4e25af36edd1ed3104fc26e77ca2c503f2af777`.
The first host attempt could not bind debug event port 755 as an unprivileged
user. A temporary low-port proxy forwarded it to the client on 1755 for the
successful run. `DEBUG_GET_THREAD_LIST` returned ERROR on a separate run and
closed that debug connection; the child still exited cleanly. The working stop
path does not rely on that command. These are disposable-child results only;
ps5debug-ng remains a separate runtime dependency and Lapy's native reference
transaction is not yet wired to this hold.
