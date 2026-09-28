#!/usr/bin/env python3
"""Validate a displaced /data root reference released by a native donor exit."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")
PHASES = ("baseline", "data_acquired", "both_held", "old_root_placed",
          "old_donor_released", "root_restored", "baseline_restored")
ROOT_DELTAS = (0, 1, 3, 3, 1, 1, 0)


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path,
            elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYOLD" or \
            not server.get("clean") or not server.get("bye") or server.get("gaps") or \
            server.get("raw_lines") != 0 or server.get("oversized_lines") != 0:
        raise ValueError("incomplete or wrong ps5log stream")
    if server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("log hash mismatch")
    build_id = build.get("build_id")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "old-root-native-donor-release" or \
            build.get("console_validated") is not False or \
            not isinstance(build_id, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", build_id) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 14 or \
            not lines[0].startswith("HELLO ps5log/1 title=LAPYOLD ") or \
            not lines[-1].startswith("BYE seq=12 ") or \
            fields(lines[-1]).get("reason") != "probe-complete" or \
            server.get("records") != 12 or server.get("last_seq") != 12:
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
            start.get("mode") != "donor-old-root-release":
        raise ValueError("wrong start identity or firmware")
    target_message, target = records[1]
    if not target_message.startswith("target_ready ") or \
            target.get("build") != build_id or \
            any(target.get(key) != "1" for key in
                ("private", "root_system", "jail_null", "cdir_system",
                 "ref_hint")):
        raise ValueError("target did not own expected private filedesc")
    for index, role, cdir in ((3, "old", "0"),
                               (5, "replacement", "1")):
        message, donor = records[index]
        if not message.startswith("donor_ready ") or \
                donor.get("build") != build_id or donor.get("role") != role or \
                donor.get("cdir_system") != cdir or \
                any(donor.get(key) != "1" for key in
                    ("private", "root_system", "jail_null", "ref_hint")):
            raise ValueError("donor did not own expected private filedesc")
    root_baseline = data_acquired = None
    for phase, root_delta, index in zip(PHASES, ROOT_DELTAS,
                                        (2, 4, 6, 7, 8, 9, 10)):
        message, sample = records[index]
        if not message.startswith("old_root_sample ") or \
                sample.get("build") != build_id or sample.get("phase") != phase:
            raise ValueError("wrong sample identity or order")
        try:
            rh, ru, dh, du = (int(sample[k]) for k in
                              ("root_hold", "root_use", "data_hold",
                               "data_use"))
        except (KeyError, ValueError) as exc:
            raise ValueError("malformed sample") from exc
        if not 1 <= rh <= 4096 or not 1 <= ru <= 4096:
            raise ValueError("implausible root sample")
        if root_baseline is None:
            root_baseline = rh, ru
        if (rh, ru) != (root_baseline[0] + root_delta,
                        root_baseline[1] + root_delta):
            raise ValueError("system root references were not balanced")
        if phase == "baseline":
            if sample.get("data_known") != "0" or (dh, du) != (0, 0):
                raise ValueError("invalid unknown data sample")
        else:
            if sample.get("data_known") != "1" or \
                    not 1 <= dh <= 4096 or not 1 <= du <= 4096:
                raise ValueError("invalid data sample")
            if data_acquired is None:
                data_acquired = dh, du
            expected = (data_acquired[0] - 1, data_acquired[1] - 1) \
                if phase == "baseline_restored" else data_acquired
            if (dh, du) != expected:
                raise ValueError("old /data root reference was not released")
    result_message, result = records[11]
    if not result_message.startswith("probe_result ") or \
            result.get("build") != build_id or \
            result.get("stage") != "complete" or result.get("error") != "0" or \
            result.get("old_reaped") != "1" or \
            result.get("replacement_reaped") != "1":
        raise ValueError("probe did not complete cleanly")
    return {"schema": "lapy-old-root-release-analysis/1",
            "build_id": build_id, "firmware": "12020000",
            "log_sha256": server["sha256"], "balanced": True,
            "scope": "native /data cwd donor and disposable root slot; no active title"}


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
