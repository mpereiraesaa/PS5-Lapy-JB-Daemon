#!/usr/bin/env python3
"""Validate native donor filedesc root-reference lifecycle evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path,
            elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYDON" or \
            not server.get("clean") or not server.get("bye") or server.get("gaps") or \
            server.get("raw_lines") != 0 or server.get("oversized_lines") != 0:
        raise ValueError("incomplete or wrong ps5log stream")
    if server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("log hash mismatch")
    build_id = build.get("build_id")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "donor-filedesc-native-rfork-read-only" or \
            build.get("console_validated") is not False or \
            not isinstance(build_id, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", build_id) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 8 or not lines[0].startswith("HELLO ps5log/1 title=LAPYDON ") or \
            not lines[-1].startswith("BYE seq=6 ") or \
            fields(lines[-1]).get("reason") != "probe-complete" or \
            server.get("records") != 6 or server.get("last_seq") != 6:
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
            start.get("mode") != "donor-rfork-read-only" or \
            start.get("firmware") != "12020000":
        raise ValueError("wrong start or firmware")
    samples = []
    for index, phase in ((1, "baseline"), (3, "held"), (4, "released")):
        message, sample = records[index]
        if not message.startswith("donor_sample ") or \
                sample.get("build") != build_id or sample.get("phase") != phase:
            raise ValueError("wrong sample identity or order")
        try:
            hold, use = int(sample["hold"]), int(sample["use"])
        except (KeyError, ValueError) as exc:
            raise ValueError("invalid sample numbers") from exc
        if not 1 <= hold <= 4096 or not 1 <= use <= 4096:
            raise ValueError("implausible sample values")
        samples.append((hold, use))
    identity_message, identity = records[2]
    if not identity_message.startswith("donor_identity ") or \
            identity.get("build") != build_id:
        raise ValueError("wrong donor identity")
    try:
        distinct, root, jail, cdir, ref_hint = (
            int(identity[k]) for k in
            ("distinct_fd", "root_system", "jail_null", "cdir_system",
             "ref_hint"))
    except (KeyError, ValueError) as exc:
        raise ValueError("malformed donor identity") from exc
    if (distinct, root, jail, ref_hint) != (1, 1, 1, 1) or cdir not in (0, 1):
        raise ValueError("donor did not own a private, expected filedesc")
    expected_refs = 1 + cdir
    if samples[1] != (samples[0][0] + expected_refs,
                      samples[0][1] + expected_refs) or \
            samples[2] != samples[0]:
        raise ValueError("donor native root references were not balanced")
    result_message, result = records[5]
    if not result_message.startswith("probe_result ") or \
            result.get("build") != build_id or \
            result.get("stage") != "complete" or \
            result.get("error") != "0" or \
            result.get("cleanup_error") != "0" or \
            result.get("child_reaped") != "1":
        raise ValueError("probe did not complete cleanly")
    return {"schema": "lapy-donor-filedesc-analysis/1",
            "build_id": build_id, "firmware": "12020000",
            "log_sha256": server["sha256"],
            "native_root_references": expected_refs,
            "balanced": True,
            "scope": "disposable private child filedesc; no pointer transfer"}


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
