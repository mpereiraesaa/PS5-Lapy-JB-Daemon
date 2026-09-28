#!/usr/bin/env python3
"""Run one identity-bound, locally stopped FW 12.02 old-root probe."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import threading
import time

from analyze_retained_nonroot import analyze


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build/retained_nonroot-probe/self-stop"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--elfldr-port", type=int, default=9021)
    args = parser.parse_args()
    manifest = BUILD / "manifest.json"
    elf = BUILD / "lapy_retained_nonroot_probe.elf"
    build = json.loads(manifest.read_text())
    identity = build["build_id"]
    if build.get("mode") != "disposable-nonroot-old-release" or \
            build.get("self_stop") is not True or \
            build.get("elf_sha256") != hashlib.sha256(elf.read_bytes()).hexdigest():
        parser.error("self-stop ELF or manifest identity mismatch")
    if not args.runs.is_dir():
        parser.error("ps5log runs directory missing")
    prior = {p.name for p in args.runs.glob("*_LAPYNROOT_*.log")}
    sender_errors = []

    def send():
        try:
            with socket.create_connection((args.host, args.elfldr_port), 5) as sock:
                sock.settimeout(35)
                sock.sendall(elf.read_bytes())
                sock.shutdown(socket.SHUT_WR)
                while sock.recv(4096):
                    pass
        except Exception as exc:
            sender_errors.append(f"{type(exc).__name__}: {exc}")

    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    deadline = time.monotonic() + 38
    selected = None
    while time.monotonic() < deadline:
        for path in args.runs.glob("*_LAPYNROOT_*.log"):
            if path.name in prior:
                continue
            content = path.read_text(errors="replace")
            if f"probe_start build={identity} " not in content:
                continue
            selected = path
            if f"probe_held build={identity} " in content:
                raise RuntimeError(f"probe_held; leave owners untouched: {path}")
            if "BYE seq=" in content:
                break
        if selected is not None and "BYE seq=" in selected.read_text(errors="replace"):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError(f"no complete identity-matched stream; latest={selected}")
    worker.join(2)
    if worker.is_alive() or sender_errors:
        raise RuntimeError(f"elfldr sender incomplete: {sender_errors}")
    server = selected.with_suffix(".json")
    for _ in range(30):
        if server.exists():
            break
        time.sleep(0.1)
    if not server.exists():
        raise RuntimeError(f"ps5log server manifest missing: {server}")
    print(json.dumps(analyze(selected, server, manifest, elf),
                     sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
