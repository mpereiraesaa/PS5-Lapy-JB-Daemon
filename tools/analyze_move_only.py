#!/usr/bin/env python3
"""Check artifact-bound move-only donor reference balance on FW 12.02."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")
SAMPLES = ((1, "baseline", 0), (3, "data_acquired", 1),
           (7, "data_installed", 7), (8, "old_root_released", 3),
           (9, "root_restored", 3), (10, "baseline_restored", 0))


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path,
            elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYMOVE" or \
            not server.get("clean") or not server.get("bye") or server.get("gaps") or \
            server.get("raw_lines") != 0 or server.get("oversized_lines") != 0 or \
            server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("incomplete or mismatched ps5log stream")
    build_id = build.get("build_id")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "move-only-donor-reference-round-trip" or \
            build.get("console_validated") is not False or \
            not isinstance(build_id, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", build_id) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 14 or \
            not lines[0].startswith("HELLO ps5log/1 title=LAPYMOVE ") or \
            not lines[-1].startswith("BYE seq=12 ") or \
            fields(lines[-1]).get("reason") != "probe-complete" or \
            server.get("records") != 12 or server.get("last_seq") != 12:
        raise ValueError("wrong HELLO, BYE or record count")
    records = []
    for seq, line in enumerate(lines[1:-1], 1):
        match = RECORD.fullmatch(line)
        if not match or int(match.group(1)) != seq or match.group(3) != "MARK":
            raise ValueError("record sequence or severity mismatch")
        records.append((match.group(4), fields(match.group(4))))
    start_message, start = records[0]
    if not start_message.startswith("probe_start ") or \
            start.get("build") != build_id or \
            start.get("firmware") != "12020000" or \
            start.get("mode") != "move-only-old-root-round-trip":
        raise ValueError("wrong start identity or firmware")
    for index, role, cwd_system in ((2, "data", "0"),
                                     (4, "root", "1"),
                                     (5, "root", "1"),
                                     (6, "root", "1")):
        message, donor = records[index]
        if not message.startswith("donor_ready ") or \
                donor.get("build") != build_id or \
                donor.get("role") != role or \
                donor.get("cwd_system") != cwd_system or \
                any(donor.get(key) != "1" for key in
                    ("private", "root_system", "jail_null", "ref_hint")):
            raise ValueError("unexpected donor ownership")
    root_baseline = data_acquired = None
    for index, phase, delta in SAMPLES:
        message, sample = records[index]
        if not message.startswith("move_sample ") or \
                sample.get("build") != build_id or \
                sample.get("phase") != phase:
            raise ValueError("sample order or identity mismatch")
        try:
            rh, ru, dh, du = (int(sample[key]) for key in
                              ("root_hold", "root_use", "data_hold",
                               "data_use"))
        except (KeyError, ValueError) as exc:
            raise ValueError("malformed sample") from exc
        if not 1 <= rh <= 4096 or not 1 <= ru <= 4096:
            raise ValueError("implausible root count")
        if root_baseline is None:
            root_baseline = rh, ru
        if (rh, ru) != (root_baseline[0] + delta,
                        root_baseline[1] + delta):
            raise ValueError("root count drift")
        if phase == "baseline":
            if sample.get("data_known") != "0" or (dh, du) != (0, 0):
                raise ValueError("invalid baseline /data sample")
        else:
            if sample.get("data_known") != "1" or \
                    not 1 <= dh <= 4096 or not 1 <= du <= 4096:
                raise ValueError("invalid /data sample")
            if data_acquired is None:
                data_acquired = dh, du
            expected = (data_acquired[0] - 1, data_acquired[1] - 1) \
                if phase == "baseline_restored" else data_acquired
            if (dh, du) != expected:
                raise ValueError("/data reference was not released")
    message, result = records[11]
    if not message.startswith("probe_result ") or \
            result.get("build") != build_id or \
            result.get("stage") != "complete" or result.get("error") != "0" or \
            any(result.get(key) != "1" for key in
                ("first", "second", "root_balanced", "data_released",
                 "all_reaped")):
        raise ValueError("probe did not complete balanced")
    return {"schema": "lapy-move-only-analysis/1", "build_id": build_id,
            "firmware": "12020000", "log_sha256": server["sha256"],
            "balanced": True,
            "scope": "disposable move-only donor /data round trip; no active title"}


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
