#!/usr/bin/env python3
"""Verify identity-bound PS5 SCM_RIGHTS transfer after sender close."""
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
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYXFD" or \
            not server.get("clean") or not server.get("bye") or \
            server.get("gaps") or server.get("raw_lines") != 0 or \
            server.get("oversized_lines") != 0 or \
            server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("incomplete or wrong ps5log stream")
    build_id = build.get("build_id")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "cross-process-root-fd" or \
            build.get("console_validated") is not False or \
            not isinstance(build_id, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", build_id) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 4 or \
            not lines[0].startswith("HELLO ps5log/1 title=LAPYXFD ") or \
            not lines[-1].startswith("BYE seq=2 ") or \
            fields(lines[-1]).get("reason") != "probe-complete" or \
            server.get("records") != 2 or server.get("last_seq") != 2:
        raise ValueError("unexpected HELLO, BYE or record count")
    records = []
    for seq, line in enumerate(lines[1:3], 1):
        record = RECORD.fullmatch(line)
        if not record or int(record.group(1)) != seq or record.group(3) != "MARK":
            raise ValueError("record sequence or level mismatch")
        records.append((record.group(4), fields(record.group(4))))
    start_message, start = records[0]
    result_message, result = records[1]
    if not start_message.startswith("probe_start ") or \
            start.get("build") != build_id or \
            start.get("mode") != "cross-process-root-fd" or \
            not result_message.startswith("probe_result ") or \
            result.get("build") != build_id:
        raise ValueError("wrong probe identity")
    try:
        firmware = int(start["firmware"], 16)
        metrics = {key: int(result[key]) for key in
                   ("error", "child_error", "parent_root_closed",
                    "child_after_close", "child_reaped")}
    except (KeyError, ValueError) as exc:
        raise ValueError("invalid numeric probe fields") from exc
    if not 0 <= firmware <= 0xffffffff or \
            result.get("stage") != "complete" or \
            metrics != {"error": 0, "child_error": 0,
                        "parent_root_closed": 1, "child_after_close": 1,
                        "child_reaped": 1}:
        raise ValueError("native transfer after sender close unproven")
    return {"schema": "lapy-cross-process-directory-analysis/1",
            "build_id": build_id, "firmware": f"{firmware:08x}",
            "log_sha256": server["sha256"], "supported": True,
            "scope": "disposable same-root processes; cross-sandbox target unverified"}


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
