#!/usr/bin/env python3
"""Verify one identity-bound ps5log/1 native filedesc unshare experiment."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_manifest: Path, build_manifest: Path,
            elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_manifest.read_text())
    build = json.loads(build_manifest.read_text())
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYFD":
        raise ValueError("wrong ps5log stream")
    if not server.get("clean") or not server.get("bye") or server.get("gaps") or \
            server.get("raw_lines") != 0 or server.get("oversized_lines") != 0:
        raise ValueError("incomplete or malformed ps5log stream")
    if server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("log identity or hash mismatch")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "self-filedesc-native-unshare" or \
            build.get("console_validated") is not False:
        raise ValueError("wrong build manifest")
    build_id = build.get("build_id")
    if not isinstance(build_id, str) or not re.fullmatch(r"[0-9a-f]{64}", build_id):
        raise ValueError("invalid build identity")
    if build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("ELF hash mismatch")

    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 4 or not lines[0].startswith("HELLO ps5log/1 title=LAPYFD "):
        raise ValueError("unexpected record count or HELLO")
    if not lines[-1].startswith("BYE seq=2 ") or \
            fields(lines[-1]).get("seq") != "2":
        raise ValueError("missing or mismatched BYE")
    parsed = []
    for seq, line in enumerate(lines[1:3], 1):
        record = RECORD.fullmatch(line)
        if not record or int(record.group(1)) != seq:
            raise ValueError("record sequence mismatch")
        parsed.append((record.group(3), record.group(4)))
    if server.get("records") != 2 or server.get("last_seq") != 2:
        raise ValueError("server record count mismatch")
    level_start, start_message = parsed[0]
    level_result, result_message = parsed[1]
    start, result = fields(start_message), fields(result_message)
    if level_start != "MARK" or not start_message.startswith("probe_start ") or \
            start.get("build") != build_id or start.get("mode") != "self-only":
        raise ValueError("wrong probe start")
    if not result_message.startswith("probe_result ") or \
            result.get("build") != build_id:
        raise ValueError("wrong probe result")
    try:
        ref_offset = int(start["ref_offset"], 16)
        firmware = int(start["firmware"], 16)
        metrics = {key: int(result[key]) for key in
                   ("error", "initial_refs", "shared_refs", "private_refs",
                    "old_refs", "shared_same", "private_new", "unshared")}
    except (KeyError, ValueError) as exc:
        raise ValueError("malformed numeric probe fields") from exc
    if not 0 <= ref_offset <= 0x200 or ref_offset % 4 or \
            not 0 <= firmware <= 0xffffffff or metrics["error"] < 0:
        raise ValueError("invalid probe fields")
    supported = metrics["error"] == 0
    if supported:
        if level_result != "MARK" or result.get("stage") != "wait_child" or \
                metrics != {"error": 0, "initial_refs": 1, "shared_refs": 2,
                            "private_refs": 1, "old_refs": 1,
                            "shared_same": 1, "private_new": 1,
                            "unshared": 1} or \
                fields(lines[-1]).get("reason") != "probe-complete":
            raise ValueError("success claim contradicts native unshare evidence")
    elif level_result != "ERR" or \
            fields(lines[-1]).get("reason") != "probe-failed":
        raise ValueError("failure result is inconsistent")
    return {"schema": "lapy-filedesc-unshare-analysis/1",
            "build_id": build_id, "firmware": f"{firmware:08x}",
            "log_sha256": server["sha256"], "supported": supported,
            "error": metrics["error"], "stage": result.get("stage"),
            "scope": "disposable probe only; target execution and root ownership unverified"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("server_manifest", type=Path)
    parser.add_argument("build_manifest", type=Path)
    parser.add_argument("elf", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.log, args.server_manifest,
                             args.build_manifest, args.elf), indent=2,
                     sort_keys=True))


if __name__ == "__main__":
    main()
