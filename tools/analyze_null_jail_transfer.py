#!/usr/bin/env python3
"""Validate a controlled two-donor null-jail reference transfer on PS5."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")
PHASES = ("baseline", "both_held", "donated", "source_released",
          "returned", "baseline_restored")
DELTAS = (0, 4, 4, 3, 3, 0)


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path,
            elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYSWAP" or \
            not server.get("clean") or not server.get("bye") or server.get("gaps") or \
            server.get("raw_lines") != 0 or server.get("oversized_lines") != 0:
        raise ValueError("incomplete or wrong ps5log stream")
    if server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("log hash mismatch")
    build_id = build.get("build_id")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "null-jail-two-donor-pointer-transfer" or \
            build.get("console_validated") is not False or \
            not isinstance(build_id, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", build_id) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 13 or \
            not lines[0].startswith("HELLO ps5log/1 title=LAPYSWAP ") or \
            not lines[-1].startswith("BYE seq=11 ") or \
            fields(lines[-1]).get("reason") != "probe-complete" or \
            server.get("records") != 11 or server.get("last_seq") != 11:
        raise ValueError("unexpected HELLO, BYE or record count")
    records = []
    for seq, line in enumerate(lines[1:-1], 1):
        record = RECORD.fullmatch(line)
        if not record or int(record.group(1)) != seq or record.group(3) != "MARK":
            raise ValueError("record sequence or level mismatch")
        records.append((record.group(4), fields(record.group(4))))
    start_message, start = records[0]
    if not start_message.startswith("probe_start ") or \
            start.get("build") != build_id or \
            start.get("firmware") != "12020000" or \
            start.get("mode") != "null-jail-two-donors":
        raise ValueError("wrong start identity or firmware")
    target_message, target = records[1]
    if not target_message.startswith("target_ready ") or \
            target.get("build") != build_id or \
            any(target.get(key) != "1" for key in
                ("private", "root_system", "jail_null", "ref_hint")):
        raise ValueError("target did not own expected private filedesc")
    for index, role in ((3, "source"), (4, "receiver")):
        message, donor = records[index]
        if not message.startswith("donor_ready ") or \
                donor.get("build") != build_id or donor.get("role") != role or \
                any(donor.get(key) != "1" for key in
                    ("private", "root_system", "jail_null", "ref_hint")):
            raise ValueError("donor did not own expected private filedesc")
    baseline = None
    for phase, delta, index in zip(PHASES, DELTAS, (2, 5, 6, 7, 8, 9)):
        message, sample = records[index]
        if not message.startswith("transfer_sample ") or \
                sample.get("build") != build_id or sample.get("phase") != phase:
            raise ValueError("wrong sample identity or order")
        try:
            hold, use = int(sample["hold"]), int(sample["use"])
        except (KeyError, ValueError) as exc:
            raise ValueError("malformed sample") from exc
        if not 1 <= hold <= 4096 or not 1 <= use <= 4096:
            raise ValueError("implausible sample values")
        if baseline is None:
            baseline = hold, use
        if (hold, use) != (baseline[0] + delta, baseline[1] + delta):
            raise ValueError("reference transfer was not balanced")
    result_message, result = records[10]
    if not result_message.startswith("probe_result ") or \
            result.get("build") != build_id or \
            result.get("stage") != "complete" or result.get("error") != "0" or \
            result.get("source_reaped") != "1" or \
            result.get("receiver_reaped") != "1" or \
            result.get("parent_jail_owned") != "0":
        raise ValueError("probe did not complete cleanly")
    return {"schema": "lapy-null-jail-transfer-analysis/1",
            "build_id": build_id, "firmware": "12020000",
            "log_sha256": server["sha256"], "balanced": True,
            "scope": "two disposable donors and one null-jail payload; no active title"}


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
