FORK STATUS (mpereiraesaa)
-------------------------
Native reference-safe repeated elevation is NOT implemented or validated yet.
The inherited lapy_jb_daemon.elf is an upstream artifact, not a fixed release.
Do not use this fork as a remedy for repeated-launch crashes yet.

The original build required a libhijacker.a that was not present in Git.
This branch adds an explicit, source-pinned LEGACY comparison build:

  PS5_PAYLOAD_SDK=/path/to/sdk/install PS5_CXXRT=/path/to/cxxrt make legacy
  make check

PS5_CXXRT is optional when the SDK already contains libc++, libc++abi and
libunwind. Output: build/legacy/lapy_jb_daemon_legacy.elf and manifest.json.
No deployment occurs. The legacy build retains unsafe kernel writes.
See docs/ELEVATION.md for evidence, limitations and the native backend contract.

Original upstream documentation follows; its runtime claims describe upstream.

================================================================================
  Lapy JB Daemon — standalone homebrew payload for PS5-Xplorer / similar apps
  v1.2 — multi-firmware (3.00 -> 12.00, every fw covered by ps5-payload-sdk)
================================================================================

WHAT IT DOES
------------
Mimics etaHEN's jailbreak-on-demand daemon API for Sony app PRXes (= the
prx.cpp shipped with PS5-Xplorer / universalps5-style apps that depend on
etaHEN being active to unsandbox themselves).

When this daemon runs, your PS5 app's PRX writes a request file to its
sandbox /download0/etahen_jailbreak with its PID. The daemon detects the
file, walks allproc, finds the process, bumps its ucred (caps + authID +
uid + attr) via libhijacker, then deletes the file. Same effect as etaHEN
doing it.

NO etaHEN required.

REQUIREMENTS
------------
 - PS5 jailbroken with kstuff active 
 - Homebrew Launcher (HBL) or autoload.txt configured

INSTALL
-------
 1. Copy the entire `lapy_jb` folder to your PS5 at :
       /data/homebrew/lapy_jb/
    (use FTP, USB, etc.)

    The folder must contain :
       lapy_jb_daemon.elf
       homebrew.js

 2. Open HBL — you should see "lapy Jb daemon" in the list.

 3. Tap to launch. Notification "Lapy JB Daemon active" will appear.

 4. Now launch your app (e.g., PS5-Xplorer) — the daemon will detect its
    jailbreak request and bump it automatically.

OPTIONAL : auto-launch at boot
-------------------------------
Add to your /data/autoload.txt :
       /data/homebrew/lapy_jb/lapy_jb_daemon.elf

So the daemon launches at every PS5 boot, no manual HBL tap needed.

KLOG (= debug)
--------------
On launch :
   [lapy_jb] Lapy JB Daemon v1.2 (multi-fw)
   [lapy_jb]   No etaHEN, no PHU required
   [lapy_jb] kernel_base = 0x...
   [lapy_jb] polling /mnt/sandbox/<TID>_<NNN>/download0/etahen_jailbreak every 250ms

When app launches :
   [lapy_jb] request from <TID>_<NNN> : pid=N
   [lapy_jb] jailbreak OK pid=N
   (caps + authid + uid + sceAttr + sandbox escape via fd_rdir/jdir applied)

If the first attempt fails ("getHijacker FAIL — process may have exited"),
just relaunch your app — second attempt usually succeeds (timing race).

BUILD FROM SOURCE
-----------------
The repo ships libhijacker (headers + static library) under extern/, so
the only external dependency is the PS5 payload SDK :

 - ps5-payload-sdk (John Törnblom) :
       https://github.com/ps5-payload-dev/sdk
   Set environment variable PS5_PAYLOAD_SDK to the SDK root.

Build :
       export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
       make

Output : lapy_jb_daemon.elf

About source/offsets_v940.cpp :
This file overrides libhijacker's vanilla offsets.cpp at link time. It's
what makes the binary multi-fw : ps5-payload-sdk already resolves kernel
symbols per-fw at boot via KERNEL_ADDRESS_* runtime externs, so
offsets_v940 just converts those absolute VAs to offsets the way
libhijacker's offsets:: namespace expects. The shipped extern/libhijacker/
libhijacker.a has been prebuilt with this override already applied — if
you bring your own vanilla libhijacker.a, the standalone offsets_v940.o
takes precedence at link time and the vanilla offsets.cpp.o stays out.

CREDITS
-------
Built on libhijacker by illusion + LightingMod.
Uses ps5-payload-sdk by John Törnblom.
Multi-fw offsets module (offsets_v940) by Team PHU / Arksama.

CHANGELOG
---------
v1.2 (2026-05-07)
  - Multi-fw : works on every PS5 fw covered by ps5-payload-sdk + kstuff
    (3.00 -> 12.00). Kernel symbols (allproc, rootvnode, security_flags,
    qa_flags, utoken_flags) auto-resolved per-fw at boot via the SDK's
    runtime KERNEL_ADDRESS_* externs (no hardcoded fw 9.40 path).
  - Same libhijacker codepath as etaHEN's daemon : caps + authid + uid +
    sceAttr at offset 0x83 + sandbox escape via fd_rdir/fd_jdir =
    rootvnode. Identical effect to "etahen jailbreak true".

v1.0 (initial)
  - fw 9.40 only.
---------------------------------------------------------------------------------------
If you like my work you can help me by supporting me via Ko-fi
Arksama
https://ko-fi.com/arksama27554
