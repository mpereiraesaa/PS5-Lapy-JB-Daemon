#!/usr/bin/env python3
"""Coordinate one FW 12.02 disposable two-root probe under a console lease."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def stream_text(path):
    return path.read_text(errors="replace") if path and path.exists() else ""


def wait_for(predicate, seconds, interval=0.1):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value is not None:
            return value
        time.sleep(interval)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ps5debug-python", type=Path, required=True,
                        help="directory containing the installed ps5debug module")
    parser.add_argument("--runs", type=Path,
                        default=ROOT.parent / "logging_server/runs")
    parser.add_argument("--elfldr-port", type=int, default=9021)
    parser.add_argument("--debug-port", type=int, default=744)
    args = parser.parse_args()
    sys.path.insert(0, str(args.ps5debug_python.resolve()))
    from ps5debug import PS5Debug, Debugger, StopAction

    out = ROOT / "build/retained_two_root-probe"
    elf = out / "lapy_retained_two_root_probe.elf"
    manifest = json.loads((out / "manifest.json").read_text())
    build = manifest["build_id"]
    if manifest["mode"] != "disposable-two-root-and-old-root-release":
        parser.error("unexpected probe mode")
    if hashlib.sha256(elf.read_bytes()).hexdigest() != manifest["elf_sha256"]:
        parser.error("ELF differs from build manifest")
    if not args.runs.is_dir():
        parser.error("ps5log run directory does not exist")
    existing = {p.name for p in args.runs.glob("*_LAPY2ROOT_*.log")}
    sender_error = []

    def send():
        try:
            with socket.create_connection((args.host, args.elfldr_port), 5) as sock:
                sock.settimeout(35)
                sock.sendall(elf.read_bytes())
                sock.shutdown(socket.SHUT_WR)
                while True:
                    try:
                        if not sock.recv(4096):
                            break
                    except socket.timeout:
                        break
        except Exception as exc:
            sender_error.append(str(exc))

    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    stream = None
    pid = None

    def target_ready():
        nonlocal stream, pid
        fresh = [p for p in args.runs.glob("*_LAPY2ROOT_*.log")
                 if p.name not in existing]
        for path in sorted(fresh, key=lambda p: p.stat().st_mtime, reverse=True):
            content = stream_text(path)
            match = re.search(r"target_ready build=([0-9a-f]{64}) pid=(\d+)", content)
            if match:
                if match.group(1) != build:
                    raise RuntimeError("fresh stream has unexpected build identity")
                stream = path
                pid = int(match.group(2))
                return pid
        return None

    if wait_for(target_ready, 12) is None:
        raise RuntimeError("no fresh identity-matched target_ready within 12 seconds")

    result = {"build_id": build, "target_pid": pid, "attach": False,
              "stop": False, "committed": False, "resume": False,
              "detach": False}
    with PS5Debug(args.host, args.debug_port, 5) as dbg:
        debugger = Debugger(dbg, listen_port=1755)
        try:
            debugger.attach(pid, timeout=5)
            result["attach"] = True
            debugger.cont(StopAction.STOP)
            result["stop"] = True

            def committed():
                content = stream_text(stream)
                if "probe_held build=" + build in content:
                    # An ambiguous transfer cannot be unwound by disconnecting
                    # the debugger. Keep this coordinator and console lease alive.
                    print("probe_held: retain debugger and console lease", flush=True)
                    while True:
                        time.sleep(1)
                if "transfer_committed build=" + build in content:
                    return True
                if "probe_result build=" + build in content:
                    raise RuntimeError("probe failed before transfer")
                return None

            if wait_for(committed, 12) is None:
                raise RuntimeError("no transfer_committed within 12 seconds")
            result["committed"] = True
            debugger.cont(StopAction.RESUME)
            result["resume"] = True
            debugger.detach()
            result["detach"] = True
        finally:
            if debugger.pid is not None:
                content = stream_text(stream)
                if "probe_held build=" + build not in content:
                    try:
                        if result["stop"] and not result["resume"]:
                            debugger.cont(StopAction.RESUME)
                    finally:
                        debugger.detach()
            debugger.close()

    worker.join(18)
    content = stream_text(stream)
    result["sender_done"] = not worker.is_alive()
    result["sender_error"] = sender_error
    result["stream_complete"] = "BYE" in content
    result["probe_complete"] = all(term in content for term in (
        "stage=complete error=0 moved=1", "first_reaped=1",
        "second_reaped=1", "target_reaped=1"))
    print(json.dumps(result, sort_keys=True), flush=True)
    if sender_error or not all(result[key] for key in
                               ("attach", "stop", "committed", "resume",
                                "detach", "sender_done", "stream_complete",
                                "probe_complete")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
