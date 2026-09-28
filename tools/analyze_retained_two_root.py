#!/usr/bin/env python3
"""Check an artifact-bound, balanced FW 12.02 two-root probe stream."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")
PHASES = ("baseline", "target_ready", "first_ready", "donors_ready",
          "transfer_committed", "first_reaped", "second_reaped",
          "target_reaped")
DELTAS = (0, 2, 4, 6, 6, 4, 3, 0)


def fields(message):
    return dict(FIELDS.findall(message))


def analyze(log_path: Path, server_path: Path, build_path: Path, elf_path: Path):
    raw = log_path.read_bytes()
    server = json.loads(server_path.read_text())
    build = json.loads(build_path.read_text())
    identity = build.get("build_id")
    if server.get("protocol") != "ps5log/1" or \
            server.get("title") != "LAPY2ROOT" or \
            not server.get("clean") or not server.get("bye") or \
            server.get("gaps") or server.get("raw_lines") != 0 or \
            server.get("oversized_lines") != 0 or \
            server.get("log_path") != log_path.name or \
            server.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("incomplete or mismatched ps5log stream")
    if build.get("schema") != "lapy-probe-build/1" or \
            build.get("mode") != "disposable-two-root-and-old-root-release" or \
            build.get("console_validated") is not False or \
            not isinstance(identity, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", identity) or \
            build.get("elf_sha256") != hashlib.sha256(elf_path.read_bytes()).hexdigest():
        raise ValueError("build or ELF identity mismatch")

    lines = raw.decode("utf-8").splitlines()
    if len(lines) < 11 or not lines[0].startswith(
            "HELLO ps5log/1 title=LAPY2ROOT ") or \
            not lines[-1].startswith("BYE seq=") or \
            fields(lines[-1]).get("reason") != "probe-complete":
        raise ValueError("missing HELLO or complete BYE")
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
    if server.get("records") != len(records) or \
            server.get("last_seq") != len(records) or \
            lines[-1].split(" ", 2)[1] != f"seq={len(records)}":
        raise ValueError("server or BYE sequence mismatch")
    first_kind, start = records[0]
    if first_kind != "probe_start" or start.get("mode") != "retained-two-root" or \
            start.get("firmware") != "12020000":
        raise ValueError("unexpected probe start or firmware")
    if records[-1][0] != "probe_result":
        raise ValueError("missing final result")
    result = records[-1][1]
    required = {"stage": "complete", "error": "0", "moved": "1",
                "first_reaped": "1", "second_reaped": "1",
                "target_reaped": "1"}
    if any(result.get(k) != v for k, v in required.items()):
        raise ValueError("transaction or native cleanup incomplete")

    samples = [(i, item) for i, (kind, item) in enumerate(records)
               if kind == "root_sample"]
    if len(samples) < len(PHASES):
        raise ValueError("missing root samples")
    baseline = None
    previous_position = -1
    observed = []
    for phase, delta in zip(PHASES, DELTAS):
        matching = [(position, item) for position, item in samples
                    if position > previous_position and item.get("phase") == phase]
        if not matching:
            raise ValueError(f"missing or out-of-order root sample {phase}")
        position, item = matching[-1] if phase == "target_reaped" else matching[0]
        previous_position = position
        try:
            hold, use = int(item["hold"]), int(item["use"])
        except (KeyError, ValueError) as exc:
            raise ValueError("invalid root counters") from exc
        if not 1 <= hold <= 4096 or not 1 <= use <= 4096:
            raise ValueError("implausible root counters")
        if baseline is None:
            baseline = (hold, use)
        if phase not in ("first_reaped", "second_reaped") and \
                (hold, use) != (baseline[0] + delta, baseline[1] + delta):
            raise ValueError(f"unbalanced root references at {phase}")
        observed.append((phase, hold, use))
    event_positions = {}
    for index, (kind, item) in enumerate(records):
        if kind in ("target_ready", "target_stopped", "transfer_committed"):
            event_positions[kind] = index
            if kind == "transfer_committed" and \
                    any(item.get(key) != "1" for key in
                        ("target_stopped", "target_root_system",
                         "target_jail_system", "first_old_root_received",
                         "donor_roots_null")):
                raise ValueError("incomplete transfer readback")
    if not (event_positions.get("target_ready", -1) <
            event_positions.get("target_stopped", -1) <
            event_positions.get("transfer_committed", -1)):
        raise ValueError("missing target stop or transfer event")
    interference = result.get("intermediate_noise") == "1"
    if result.get("intermediate_noise") not in ("0", "1"):
        raise ValueError("invalid interference flag")
    if not interference:
        for (phase, hold, use), delta in zip(observed, DELTAS):
            if (hold, use) != (baseline[0] + delta, baseline[1] + delta):
                raise ValueError(f"unbalanced root references at {phase}")
    return {"schema": "lapy-two-root-analysis/1", "build_id": identity,
            "log_sha256": server["sha256"], "balanced": True,
            "intermediate_interference": interference,
            "baseline_hold": baseline[0], "baseline_use": baseline[1],
            "scope": "disposable FW 12.02 processes only"}


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
