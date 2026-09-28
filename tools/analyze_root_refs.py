#!/usr/bin/env python3
"""Validate a private ps5log/1 root-reference run and summarize small fields."""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
import re

FIELD = re.compile(r"([a-z_]+)=([^ ]+)")
RECORD = re.compile(r"(\d+)\t(\d+)\t([A-Z]+)\t(.*)")


def fields(message):
    return dict(FIELD.findall(message))


def analyze(log_path: Path, server_manifest: Path, build_manifest: Path):
    raw = log_path.read_bytes()
    metadata = json.loads(server_manifest.read_text())
    build = json.loads(build_manifest.read_text())
    if metadata.get("protocol") != "ps5log/1" or metadata.get("title") != "LAPYREF":
        raise ValueError("wrong logging protocol or probe identity")
    if not metadata.get("clean") or not metadata.get("bye") or metadata.get("gaps"):
        raise ValueError("incomplete ps5log run")
    if metadata.get("raw_lines") != 0 or metadata.get("oversized_lines") != 0:
        raise ValueError("malformed or oversized logging record")
    if metadata.get("log_path") != log_path.name:
        raise ValueError("server manifest names another log")
    if hashlib.sha256(raw).hexdigest() != metadata.get("sha256"):
        raise ValueError("log hash differs from server manifest")
    if build.get("mode") != "root-vnode-read-only" or build.get("console_validated") is not False:
        raise ValueError("wrong build manifest")
    build_id = build.get("build_id")
    if not isinstance(build_id, str) or len(build_id) != 64:
        raise ValueError("invalid build ID")

    lines = raw.decode("utf-8").splitlines()
    if not lines or not lines[0].startswith("HELLO ps5log/1 title=LAPYREF "):
        raise ValueError("missing expected HELLO")
    if not lines[-1].startswith("BYE seq="):
        raise ValueError("missing BYE")
    aggregates = defaultdict(lambda: {"events": 0, "net": 0, "negative": 0,
                                  "positive": 0})
    first = result = None
    last_seq = 0
    for line in lines[1:-1]:
        record = RECORD.fullmatch(line)
        if not record:
            raise ValueError("non-ps5log record")
        seq = int(record.group(1))
        if seq != last_seq + 1:
            raise ValueError("sequence gap or duplicate")
        last_seq = seq
        msg = record.group(4)
        info = fields(msg)
        if msg.startswith("probe_start "):
            if first is not None or info.get("build") != build_id:
                raise ValueError("unexpected probe start")
            first = info
        elif msg.startswith("candidate_change "):
            if info.get("build") != build_id:
                raise ValueError("candidate from another build")
            try:
                offset = int(info["offset"], 16)
                before = int(info["before"])
                after = int(info["after"])
                delta = int(info["delta"])
            except (KeyError, ValueError) as exc:
                raise ValueError("malformed candidate") from exc
            if offset < 0 or offset > 0x1c0 or offset % 4 or \
                    not 1 <= before <= 4096 or not 1 <= after <= 4096 or \
                    delta != after - before or not -8 <= delta <= 8 or delta == 0:
                raise ValueError("candidate outside probe contract")
            summary = aggregates[offset]
            summary["events"] += 1
            summary["net"] += delta
            summary["negative" if delta < 0 else "positive"] += 1
        elif msg.startswith("probe_result "):
            if result is not None or info.get("build") != build_id:
                raise ValueError("unexpected probe result")
            result = info
    if not first or not result or result.get("stage") != "complete" or \
            result.get("error") != "0" or result.get("sampled") != first.get("samples"):
        raise ValueError("probe did not complete the declared window")
    if int(result.get("changes", -1)) != sum(x["events"] for x in aggregates.values()):
        raise ValueError("candidate count mismatch")
    if int(metadata.get("records", -1)) != last_seq or \
            int(metadata.get("last_seq", -1)) != last_seq:
        raise ValueError("record count mismatch")
    if fields(lines[-1]).get("seq") != str(last_seq):
        raise ValueError("BYE sequence mismatch")
    return {
        "schema": "lapy-root-ref-analysis/1",
        "build_id": build_id,
        "log_sha256": metadata["sha256"],
        "firmware": first.get("firmware"),
        "samples": int(result["sampled"]),
        "candidates": [dict(offset=f"0x{offset:x}", **value)
                       for offset, value in sorted(aggregates.items())],
        "interpretation": "observations only; correlate with bounded escalation events",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("server_manifest", type=Path)
    parser.add_argument("build_manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.log, args.server_manifest,
                             args.build_manifest), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
