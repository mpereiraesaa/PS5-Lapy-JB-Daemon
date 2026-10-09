#!/usr/bin/env python3
"""Send the read-only exit-lifetime probe and preserve its ps5log stream."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import socket
import threading
import time


ROOT = Path(__file__).resolve().parents[1]


def evaluate_stream(manifest, stream, klog_text, sender_errors):
    text = stream.decode("utf-8", "replace")
    proof = (f"build={manifest['build_id']}" in text and
             "stopped_kill_guard " in text and
             "external_kill_queued=1" in text and
             "fd_retained=1" in text and
             "target_exit_lifetime " in text and
             "retained_proc=1" in text and "fd_cleared=1" in text and
             "exit_lifetime_result " in text and "killed=1" in text and
             "stopped_fd_retained=1" in text and
             "reaped=1" in text and "stage=complete error=0" in text and
             "BYE " in text)
    return {"build_id": manifest["build_id"],
            "elf_sha256": manifest["elf_sha256"],
            "proof": proof,
            "kernel_panic": "panic" in klog_text.lower(),
            "sender_errors": sender_errors,
            "stream_sha256": hashlib.sha256(stream).hexdigest()}


def receive_klog(host, port, path, done):
    try:
        with socket.create_connection((host, port), 5) as link, path.open("wb") as out:
            link.settimeout(1)
            while not done.is_set():
                try:
                    data = link.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                out.write(data)
                out.flush()
    except OSError as error:
        path.write_text(f"klog unavailable: {error}\n")


def send_elf(host, port, elf, path, errors):
    try:
        with socket.create_connection((host, port), 5) as link, path.open("wb") as out:
            link.sendall(elf.read_bytes())
            link.shutdown(socket.SHUT_WR)
            link.settimeout(1)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                try:
                    data = link.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                out.write(data)
    except OSError as error:
        errors.append(str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--title", default="PPSA99994")
    parser.add_argument("--elf-port", type=int, default=9021)
    parser.add_argument("--klog-port", type=int, default=3232)
    parser.add_argument("--log-port", type=int, default=9300)
    args = parser.parse_args()

    artifact = ROOT / f"build/live_target_ptrace-probe/{args.title}/exit-lifetime"
    elf = artifact / "lapy_live_target_ptrace_probe.elf"
    manifest = json.loads((artifact / "manifest.json").read_text())
    digest = hashlib.sha256(elf.read_bytes()).hexdigest()
    if manifest["mode"] != "live-title-exit-lifetime-read-only" or \
            manifest["target_title"] != args.title or \
            not manifest.get("log_server") or \
            manifest["elf_sha256"] != digest:
        parser.error("probe artifact identity mismatch")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = artifact / "runs" / stamp
    run.mkdir(parents=True)
    done = threading.Event()
    errors = []
    klog = threading.Thread(target=receive_klog,
                            args=(args.host, args.klog_port, run / "klog.txt", done),
                            daemon=True)
    klog.start()
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("", args.log_port))
        listener.listen(1)
        listener.settimeout(10)
        sender = threading.Thread(target=send_elf,
                                  args=(args.host, args.elf_port, elf,
                                        run / "elfldr.txt", errors), daemon=True)
        sender.start()
        print(f"Sent {digest}; waiting for LAPYTP on TCP {args.log_port}", flush=True)
        connection, peer = listener.accept()
        print(f"Probe connected from {peer[0]}; launch {args.title} now", flush=True)
        connection.settimeout(1)
        stream = bytearray()
        deadline = time.monotonic() + 75
        with connection:
            while time.monotonic() < deadline:
                try:
                    data = connection.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                stream.extend(data)
                print(data.decode("utf-8", "replace"), end="", flush=True)
                if b"BYE " in stream:
                    break
    done.set()
    sender.join(5)
    klog.join(5)
    (run / "stream.log").write_bytes(stream)
    klog_text = (run / "klog.txt").read_text(errors="replace")
    result = evaluate_stream(manifest, stream, klog_text, errors)
    (run / "run.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True), flush=True)
    if errors or not result["proof"] or result["kernel_panic"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
