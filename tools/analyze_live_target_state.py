#!/usr/bin/env python3
"""Validate read-only stopped-title pre-elevation state and artifact identity."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_][a-z0-9_]*)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")
FLAGS = ("root_null", "root_system", "jail_null", "jail_system",
         "cwd_null", "cwd_system", "root_jail_same", "cwd_root_same",
         "uid_root", "ruid_root", "svuid_root", "rgid_root",
         "prison0", "system_authid", "full_caps", "attrs80",
         "credential_stable")


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path, elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    identity = build.get("build_id")
    title = build.get("target_title")
    if server.get("protocol") != "ps5log/1" or \
            server.get("title") != "LAPYTS" or \
            not server.get("clean") or not server.get("bye") or \
            server.get("gaps") or server.get("raw_lines") != 0 or \
            server.get("oversized_lines") != 0 or \
            server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("incomplete or mismatched ps5log stream")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "live-title-signal-stop-read-only" or \
            build.get("observe_state") is not True or \
            build.get("console_validated") is not False or \
            not isinstance(title, str) or not re.fullmatch(r"PPSA[0-9]{5}", title) or \
            not isinstance(identity, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", identity) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 5 or not lines[0].startswith(
            "HELLO ps5log/1 title=LAPYTS ") or \
            lines[-1] != "BYE seq=3 reason=probe-complete":
        raise ValueError("wrong HELLO, BYE or record count")
    records = []
    for number, line in enumerate(lines[1:-1], 1):
        match = RECORD.fullmatch(line)
        if not match or int(match.group(1)) != number or match.group(3) != "MARK":
            raise ValueError("record sequence or severity mismatch")
        message = match.group(4)
        item = fields(message)
        if item.get("build") != identity:
            raise ValueError("record build identity mismatch")
        records.append((message.split(" ", 1)[0], item))
    if server.get("records") != 3 or server.get("last_seq") != 3:
        raise ValueError("server record count mismatch")
    (start_kind, start), (state_kind, state), (result_kind, result) = records
    if (start_kind, state_kind, result_kind) != (
            "probe_start", "target_state", "probe_result") or \
            start.get("firmware") != "12020000" or \
            start.get("mode") != "live-title-stop-read-only" or \
            start.get("title") != title or start.get("observe_state") != "1" or \
            state.get("title") != title:
        raise ValueError("wrong stopped-title probe identity")
    required = {"stage": "complete", "error": "0", "stop_sent": "1",
                "resume_sent": "1", "acknowledged": "1",
                "stable_stop": "1", "private_fd": "1"}
    if any(result.get(k) != v for k, v in required.items()):
        raise ValueError("target was not privately stopped and resumed")
    try:
        thread_count = int(result["threads"])
        suspended = int(result["suspended"])
        pid = int(result["target_pid"])
        flags = {name: int(state[name]) for name in FLAGS}
    except (KeyError, ValueError) as exc:
        raise ValueError("invalid target state") from exc
    if pid <= 1 or thread_count < 1 or suspended != thread_count or \
            any(value not in (0, 1) for value in flags.values()) or \
            flags["credential_stable"] != 1 or flags["root_null"] != 0 or \
            flags["cwd_null"] != 0:
        raise ValueError("invalid stable target identity or directory state")
    for stem in ("root", "jail", "cwd"):
        if flags[f"{stem}_null"] and flags[f"{stem}_system"]:
            raise ValueError("contradictory directory identity")
    if flags["root_system"] and flags["jail_system"] and \
            not flags["root_jail_same"]:
        raise ValueError("contradictory root/jail alias")
    if flags["jail_null"] and flags["root_jail_same"]:
        raise ValueError("null jail cannot alias a nonnull root")
    if flags["root_system"] and flags["cwd_system"] and \
            not flags["cwd_root_same"]:
        raise ValueError("contradictory cwd/root alias")
    return {"schema": "lapy-live-target-state-analysis/1", "build_id": identity,
            "title": title, "pid": pid, "threads": thread_count,
            "log_sha256": server["sha256"], "private_filedesc": True,
            "stopped_and_resumed": True, **flags,
            "scope": "one read-only FW 12.02 stopped-title snapshot"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("server_manifest", type=Path)
    parser.add_argument("build_manifest", type=Path)
    parser.add_argument("elf", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.log, args.server_manifest,
                             args.build_manifest, args.elf),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
