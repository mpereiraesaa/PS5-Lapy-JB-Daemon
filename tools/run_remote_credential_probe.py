#!/usr/bin/env python3
"""One-shot native seteuid syscall in a disposable stopped PS5 child."""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import socket
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SYS_SETEUID = 183
GADGET = b"\x0f\x05\xcc"  # syscall; int3; verified in child memory before use


def stream_text(path):
    return path.read_text(errors="replace") if path and path.exists() else ""


def wait_for(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result is not None:
            return result
        time.sleep(0.1)
    return None


def hold(reason):
    print("UNRESOLVED DEBUG STOP: " + reason, flush=True)
    while True:
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ps5debug-python", type=Path, required=True)
    parser.add_argument("--runs", type=Path,
                        default=ROOT.parent / "logging_server/runs")
    parser.add_argument("--elfldr-port", type=int, default=9021)
    parser.add_argument("--debug-port", type=int, default=744)
    args = parser.parse_args()
    sys.path.insert(0, str(args.ps5debug_python.resolve()))
    from ps5debug import PS5Debug, Debugger, StopAction

    out = ROOT / "build/remote_credential_clone-probe"
    elf = out / "lapy_remote_credential_clone_probe.elf"
    manifest = json.loads((out / "manifest.json").read_text())
    build = manifest["build_id"]
    if manifest["mode"] != "disposable-remote-native-credential-clone" or \
            hashlib.sha256(elf.read_bytes()).hexdigest() != manifest["elf_sha256"]:
        parser.error("probe artifact identity mismatch")
    if not args.runs.is_dir():
        parser.error("ps5log run directory is missing")
    existing = {p.name for p in args.runs.glob("*_LAPYRCL_*.log")}
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
    target = None

    def child_ready():
        nonlocal stream, target
        fresh = [p for p in args.runs.glob("*_LAPYRCL_*.log")
                 if p.name not in existing]
        for path in sorted(fresh, key=lambda p: p.stat().st_mtime, reverse=True):
            match = re.search(
                r"child_ready build=([0-9a-f]{64}) pid=(\d+) euid=(\d+) gadget=([0-9a-f]+)",
                stream_text(path))
            if match:
                if match.group(1) != build:
                    raise RuntimeError("unexpected fresh build identity")
                stream = path
                target = (int(match.group(2)), int(match.group(3)),
                          int(match.group(4), 16))
                return target
        return None

    if wait_for(child_ready, 12) is None:
        raise RuntimeError("no fresh identity-matched child_ready")
    pid, euid, gadget = target
    result = {"build_id": build, "target_pid": pid, "attached": False,
              "stopped": False, "gadget_verified": False,
              "syscall_success": False, "registers_restored": False,
              "clone_observed": False, "resumed": False, "detached": False}
    with PS5Debug(args.host, args.debug_port, 5) as dbg:
        debugger = Debugger(dbg, listen_port=1755)
        try:
            debugger.attach(pid, timeout=5)
            result["attached"] = True
            debugger.cont(StopAction.STOP)
            result["stopped"] = True
            threads = debugger.get_thread_list()
            if len(threads) != 1:
                raise RuntimeError("expected a single disposable child thread")
            tid = threads[0]
            if dbg.read_memory(pid, gadget, len(GADGET)) != GADGET:
                raise RuntimeError("syscall gadget bytes differ from verified ELF")
            result["gadget_verified"] = True
            original = debugger.get_regs(tid)
            injected = replace(original, rip=gadget, rax=SYS_SETEUID,
                               rdi=euid)
            debugger.set_regs(tid, injected)
            try:
                debugger.step()
                event = debugger.wait_event(timeout=5)
                observed = debugger.get_regs(tid)
            except Exception as exc:
                hold("step outcome uncertain: " + str(exc))
            if event.lwpid != tid:
                hold("step event belongs to another thread")
            if observed.rip != gadget + 2:
                hold("step did not stop immediately after syscall")
            debugger.set_regs(tid, original)
            restored = debugger.get_regs(tid)
            if restored.to_bytes() != original.to_bytes():
                hold("original register state was not restored")
            result["registers_restored"] = True
            if observed.rax != 0 or observed.rflags & 1:
                raise RuntimeError("native seteuid returned an error")
            result["syscall_success"] = True
            def clone_observed():
                content = stream_text(stream)
                if "probe_held build=" + build in content:
                    hold("parent retained stopped child after clone failure")
                if "native_clone_observed build=" + build in content:
                    return True
                return None

            result["clone_observed"] = wait_for(clone_observed, 5) is True
            debugger.cont(StopAction.RESUME)
            result["resumed"] = True
            debugger.detach()
            result["detached"] = True
        finally:
            if debugger.pid is not None:
                if result["registers_restored"] or not result["gadget_verified"]:
                    try:
                        if result["stopped"] and not result["resumed"]:
                            debugger.cont(StopAction.RESUME)
                    finally:
                        debugger.detach()
                else:
                    hold("register state uncertain; keep debugger and child stopped")
            debugger.close()
    worker.join(15)
    content = stream_text(stream)
    result["sender_done"] = not worker.is_alive()
    result["sender_error"] = sender_error
    result["stream_complete"] = "BYE" in content
    result["probe_complete"] = "stage=complete error=0 cloned=1 reaped=1" in content
    print(json.dumps(result, sort_keys=True), flush=True)
    if sender_error or not all(result[key] for key in
                               ("attached", "stopped", "gadget_verified",
                                "syscall_success", "registers_restored",
                                "clone_observed", "resumed", "detached",
                                "sender_done", "stream_complete", "probe_complete")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
