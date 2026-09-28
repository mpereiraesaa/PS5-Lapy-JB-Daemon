#!/usr/bin/env python3
"""Validate an identity-bound ps5log/1 live request directory observation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")
FLAGS = ("stable", "acknowledged", "root_null", "root_system",
         "jail_null", "jail_system", "root_jail_same", "ref_hint_valid")


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path,
            elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYREQ" or \
            not server.get("clean") or not server.get("bye") or server.get("gaps") or \
            server.get("raw_lines") != 0 or server.get("oversized_lines") != 0:
        raise ValueError("wrong or incomplete ps5log stream")
    if server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("stream identity or hash mismatch")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "live-request-directory-read-only" or \
            build.get("console_validated") is not False:
        raise ValueError("wrong build manifest")
    build_id = build.get("build_id")
    if not isinstance(build_id, str) or not re.fullmatch(r"[0-9a-f]{64}", build_id):
        raise ValueError("invalid build identity")
    if hashlib.sha256(elf_path.read_bytes()).hexdigest() != build.get("elf_sha256"):
        raise ValueError("ELF hash mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 4 or not lines[0].startswith("HELLO ps5log/1 title=LAPYREQ "):
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
            start.get("build") != build_id or start.get("mode") != "request-read-only":
        raise ValueError("wrong probe start")
    if not result_msg.startswith("probe_result ") or result.get("build") != build_id:
        raise ValueError("wrong probe result")
    try:
        firmware = int(start["firmware"], 16)
        max_polls = int(start["max_polls"])
        error = int(result["error"])
        polls = int(result["polls"])
        pid = int(result["target_pid"])
        ref_hint = int(result["ref_hint"])
        flags = {name: int(result[name]) for name in FLAGS}
    except (KeyError, ValueError) as exc:
        raise ValueError("malformed probe fields") from exc
    if not 0 <= firmware <= 0xffffffff or max_polls != 600 or \
            error < 0 or not 0 <= polls <= max_polls or \
            not -1 <= pid <= 2147483647 or ref_hint < 0 or \
            any(value not in (0, 1) for value in flags.values()):
        raise ValueError("invalid probe fields")
    observed = error == 0
    if observed:
        if result_level != "MARK" or result.get("stage") != "complete" or \
                fields(lines[-1]).get("reason") != "probe-complete" or \
                not 2 <= pid <= 2147483647 or polls >= max_polls or \
                flags["stable"] != 1 or flags["acknowledged"] != 1 or \
                flags["root_null"] or (flags["jail_null"] and flags["jail_system"]) or \
                (flags["root_jail_same"] and
                 (flags["jail_null"] or flags["root_system"] != flags["jail_system"])) or \
                (firmware == 0x12020000 and
                 (flags["ref_hint_valid"] != 1 or not 1 <= ref_hint <= 4096)) or \
                (firmware != 0x12020000 and
                 (flags["ref_hint_valid"] or ref_hint)):
            raise ValueError("observation contradicts directory identities")
    elif result_level != "ERR" or \
            fields(lines[-1]).get("reason") != "probe-failed" or \
            any(flags[name] for name in FLAGS if name not in ("stable", "acknowledged")) or \
            ref_hint:
        raise ValueError("failure result is inconsistent")
    return {"schema": "lapy-request-directory-analysis/1",
            "build_id": build_id, "firmware": f"{firmware:08x}",
            "log_sha256": server["sha256"], "observed": observed,
            "error": error, "target_pid": pid if observed else None,
            "jail_null": bool(flags["jail_null"]) if observed else None,
            "root_system": bool(flags["root_system"]) if observed else None,
            "jail_system": bool(flags["jail_system"]) if observed else None,
            "root_jail_same": bool(flags["root_jail_same"]) if observed else None,
            "filedesc_ref_hint": ref_hint if observed and flags["ref_hint_valid"] else None,
            "scope": "two pre-elevation snapshots; no process lifetime retained"}


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
