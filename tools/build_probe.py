"""Build the bounded PS5 transport probe; never deploy it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", default=os.environ.get("PS5_PAYLOAD_SDK"), required=not os.environ.get("PS5_PAYLOAD_SDK"))
    parser.add_argument("--logging-client", type=Path, required=True)
    args = parser.parse_args()
    sdk = Path(args.sdk).resolve()
    logging = args.logging_client.resolve()
    files = [ROOT / "source" / name for name in
             ("native_probe.c", "native_directory.c", "native_directory.h")]
    inputs = {str(p.relative_to(ROOT)): sha(p) for p in files}
    inputs["external/ps5log.h"] = sha(logging / "ps5log.h")
    inputs["tools/build_probe.py"] = sha(Path(__file__).resolve())
    sdk_inputs = {str(p.relative_to(sdk)): sha(p)
                  for p in sorted((sdk / "target").rglob("*")) if p.is_file()}
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    identity = hashlib.sha256(json.dumps({"inputs": inputs, "sdk": sdk_inputs,
                                         "flags": flags}, sort_keys=True).encode()).hexdigest()
    output = ROOT / "build/probe"
    output.mkdir(parents=True, exist_ok=True)
    header = output / "probe_identity.h"
    header.write_text('#define LAPY_PROBE_ID "' + identity + '"\n')
    elf = output / "lapy_native_probe.elf"
    manifest = output / "manifest.json"
    elf.unlink(missing_ok=True)
    manifest.unlink(missing_ok=True)
    command = [str(sdk / "bin/prospero-clang"), *flags, "-I" + str(logging),
               "-I" + str(output), "-I" + str(ROOT / "source"),
               str(files[0]), str(files[1]), "-o", str(elf)]
    with (output / "build.log").open("w") as log:
        log.write(json.dumps(command) + "\n")
        log.flush()
        subprocess.run(command, check=True, stdout=log, stderr=log)
    if elf.read_bytes()[:4] != b"\x7fELF":
        raise RuntimeError("Output is not ELF")
    manifest.write_text(json.dumps({"schema": "lapy-probe-build/1", "build_id": identity,
                                   "inputs_sha256": inputs, "sdk_inputs_sha256": sdk_inputs,
                                   "elf_sha256": sha(elf), "mode": "transport-only",
                                   "console_validated": False}, indent=2, sort_keys=True) + "\n")
    print(f"Built {elf.relative_to(ROOT)}\nbuild_id={identity}\nsha256={sha(elf)}")


if __name__ == "__main__":
    main()
