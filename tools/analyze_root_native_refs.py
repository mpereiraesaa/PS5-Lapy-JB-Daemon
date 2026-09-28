#!/usr/bin/env python3
"""Verify artifact-bound native root-vnode open/close reference evidence."""
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
    if server.get("protocol") != "ps5log/1" or server.get("title") != "LAPYOWN" or \
            not server.get("clean") or not server.get("bye") or \
            server.get("gaps") or server.get("raw_lines") != 0 or \
            server.get("oversized_lines") != 0:
        raise ValueError("incomplete or wrong ps5log stream")
    if server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("log hash mismatch")
    build_id = build.get("build_id")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "root-vnode-native-open-close" or \
            build.get("console_validated") is not False or \
            not isinstance(build_id, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", build_id) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")

    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 14 or not lines[0].startswith("HELLO ps5log/1 title=LAPYOWN ") or \
            not lines[-1].startswith("BYE seq=12 ") or \
            fields(lines[-1]).get("reason") != "probe-complete":
        raise ValueError("unexpected HELLO, BYE or record count")
    records = []
    for seq, line in enumerate(lines[1:-1], 1):
        record = RECORD.fullmatch(line)
        if not record or int(record.group(1)) != seq or record.group(3) != "MARK":
            raise ValueError("record sequence or level mismatch")
        records.append((record.group(4), fields(record.group(4))))
    if server.get("records") != 12 or server.get("last_seq") != 12:
        raise ValueError("server record count mismatch")

    start_message, start = records[0]
    identity_message, identity = records[1]
    if not start_message.startswith("probe_start ") or \
            start.get("build") != build_id or \
            start.get("mode") != "native-open-close" or \
            start.get("count") != "4" or \
            not identity_message.startswith("directory_identity ") or \
            identity.get("build") != build_id:
        raise ValueError("wrong start or directory identity")
    try:
        firmware = int(start["firmware"], 16)
        directory = {k: int(identity[k]) for k in
                     ("root_null", "root_system", "jail_null", "jail_system")}
    except (KeyError, ValueError) as exc:
        raise ValueError("invalid firmware or directory identity") from exc
    if not 0 <= firmware <= 0xffffffff or \
            any(value not in (0, 1) for value in directory.values()) or \
            directory["root_null"] + directory["root_system"] != 1 or \
            directory["jail_null"] + directory["jail_system"] != 1:
        raise ValueError("root path cannot be attributed to system root")

    baseline = None
    for index, (message, sample) in enumerate(records[2:11]):
        if not message.startswith("native_sample ") or sample.get("build") != build_id or \
                sample.get("hold_offset") != "0x1bc" or \
                sample.get("use_offset") != "0x1c0":
            raise ValueError("wrong native sample identity or offsets")
        try:
            hold, use, step = (int(sample[k]) for k in ("hold", "use", "step"))
        except (KeyError, ValueError) as exc:
            raise ValueError("invalid sample numbers") from exc
        if not 1 <= hold <= 4096 or not 1 <= use <= 4096:
            raise ValueError("implausible sample values")
        phase = "baseline" if index == 0 else "held" if index <= 4 else "released"
        expected_step = 0 if index == 0 else index if index <= 4 else index - 4
        if sample.get("phase") != phase or step != expected_step:
            raise ValueError("wrong native operation order")
        if index == 0:
            baseline = (hold, use)
        else:
            expected_delta = index if index <= 4 else 8 - index
            if (hold, use) != (baseline[0] + expected_delta,
                               baseline[1] + expected_delta):
                raise ValueError("unbalanced or noisy reference transition")
    result_message, result = records[11]
    if not result_message.startswith("probe_result ") or \
            result.get("build") != build_id or \
            result.get("stage") != "complete" or \
            result.get("error") != "0" or \
            result.get("cleanup_error") != "0":
        raise ValueError("probe did not complete cleanly")
    return {"schema": "lapy-root-native-ref-analysis/1",
            "build_id": build_id, "firmware": f"{firmware:08x}",
            "log_sha256": server["sha256"],
            "root_directory": "null" if directory["root_null"] else "system",
            "jail_directory": "null" if directory["jail_null"] else "system",
            "baseline_hold": baseline[0], "baseline_use": baseline[1],
            "native_descriptors": 4, "balanced": True,
            "scope": "disposable process and observed root vnode only"}


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
