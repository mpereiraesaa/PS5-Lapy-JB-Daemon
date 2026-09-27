#!/usr/bin/env python3
"""Verify a private ps5log/1 read-only target directory observation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")
FLAGS = ("stable", "root_nonnull", "jail_nonnull", "root_jail_same",
         "system_known", "root_system", "jail_system")


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path,
            elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYDIR" or \
            not server.get("clean") or not server.get("bye") or server.get("gaps") or \
            server.get("raw_lines") != 0 or server.get("oversized_lines") != 0:
        raise ValueError("wrong or incomplete ps5log stream")
    if server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("stream identity or hash mismatch")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "target-directory-read-only" or \
            build.get("console_validated") is not False:
        raise ValueError("wrong build manifest")
    build_id, pid = build.get("build_id"), build.get("target_pid")
    if not isinstance(build_id, str) or not re.fullmatch(r"[0-9a-f]{64}", build_id) or \
            not isinstance(pid, int) or not 2 <= pid <= 2147483647:
        raise ValueError("invalid build identity or target PID")
    if hashlib.sha256(elf_path.read_bytes()).hexdigest() != build.get("elf_sha256"):
        raise ValueError("ELF hash mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 4 or not lines[0].startswith("HELLO ps5log/1 title=LAPYDIR "):
        raise ValueError("unexpected record count or HELLO")
    if not lines[-1].startswith("BYE seq=2 ") or \
            fields(lines[-1]).get("seq") != "2" or \
            server.get("records") != 2 or server.get("last_seq") != 2:
        raise ValueError("mismatched BYE or record count")
    decoded = []
    for seq, line in enumerate(lines[1:3], 1):
        record = RECORD.fullmatch(line)
        if not record or int(record.group(1)) != seq:
            raise ValueError("record sequence mismatch")
        decoded.append((record.group(3), record.group(4)))
    start_level, start_msg = decoded[0]
    result_level, result_msg = decoded[1]
    start, result = fields(start_msg), fields(result_msg)
    if start_level != "MARK" or not start_msg.startswith("probe_start ") or \
            start.get("build") != build_id or start.get("mode") != "read-only" or \
            start.get("target_pid") != str(pid):
        raise ValueError("wrong probe start")
    if not result_msg.startswith("probe_result ") or \
            result.get("build") != build_id or result.get("target_pid") != str(pid):
        raise ValueError("wrong probe result")
    try:
        firmware = int(start["firmware"], 16)
        error = int(result["error"])
        flags = {name: int(result[name]) for name in FLAGS}
    except (KeyError, ValueError) as exc:
        raise ValueError("malformed probe fields") from exc
    if not 0 <= firmware <= 0xffffffff or error < 0 or \
            any(value not in (0, 1) for value in flags.values()):
        raise ValueError("invalid probe fields")
    observed = error == 0
    if observed:
        if result_level != "MARK" or result.get("stage") != "complete" or \
                fields(lines[-1]).get("reason") != "probe-complete" or \
                flags["stable"] != 1 or flags["root_nonnull"] != 1 or \
                (flags["root_jail_same"] and not flags["jail_nonnull"]) or \
                (not flags["system_known"] and
                 (flags["root_system"] or flags["jail_system"])) or \
                (not flags["jail_nonnull"] and flags["jail_system"]) or \
                (flags["root_jail_same"] and
                 flags["root_system"] != flags["jail_system"]):
            raise ValueError("observation contradicts directory identities")
    elif result_level != "ERR" or \
            fields(lines[-1]).get("reason") != "probe-failed" or \
            any(flags.values()):
        raise ValueError("failure result is inconsistent")
    return {"schema": "lapy-target-directory-analysis/1",
            "build_id": build_id, "target_pid": pid,
            "firmware": f"{firmware:08x}", "log_sha256": server["sha256"],
            "observed": observed, "error": error,
            "jail_nonnull": bool(flags["jail_nonnull"]) if observed else None,
            "root_jail_same": bool(flags["root_jail_same"]) if observed else None,
            "scope": "two read-only snapshots; process lifetime not retained"}


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
