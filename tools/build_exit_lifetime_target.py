#!/usr/bin/env python3
"""Build the disposable PPSA99999 marker title from an existing boilerplate build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TITLE = "PPSA99999"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env=None):
    subprocess.run([str(value) for value in command], check=True, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boilerplate", type=Path, required=True)
    args = parser.parse_args()
    boilerplate = args.boilerplate.resolve()
    sdk = boilerplate / ".deps/native/ps5-payload-sdk"
    compiler = boilerplate / "tooling/prospero-clang18"
    native_tool = boilerplate / "build/host/ps5-native-tool"
    source = ROOT / "examples/exit_lifetime_target_main.cpp"
    objects = [boilerplate / "build/obj/app_crt.o",
               boilerplate / "build/obj/app_cpp_runtime.o",
               boilerplate / "build/obj/src/demo_renderer.cpp.o"]
    base_package = boilerplate / f"dist/{TITLE}"
    required = [source, compiler, native_tool, *objects,
                base_package / "sce_sys/param.json"]
    if not all(path.exists() for path in required):
        parser.error("boilerplate must have a completed PPSA99999 Folder build")

    out = ROOT / f"build/exit-lifetime-target/{TITLE}"
    out.mkdir(parents=True, exist_ok=True)
    target_object = out / "target_main.o"
    linked = out / "llvm-pie.elf"
    converted = out / "eboot.elf"
    env = {**os.environ, "PS5_PAYLOAD_SDK": str(sdk),
           "PS5_CLANG": shutil.which("clang-18") or "clang-18",
           "USE_CCACHE": "1"}
    run(["sh", compiler, "-std=c++20", "-O2", "-Wall", "-Wextra",
         "-Werror", "-fno-exceptions", "-fno-rtti", "-ffunction-sections",
         "-fdata-sections", f"-I{boilerplate / 'src'}", "-c", source,
         "-o", target_object], env)
    libraries = sorted((sdk / "target/lib").glob("*.so"))
    run([sdk / "bin/prospero-lld", "-T",
         boilerplate / "tooling/native/ps5-pie.ld", "--eh-frame-hdr",
         "--version-script", boilerplate / "tooling/native/app-symbols.map",
         "-e", "_start", "-o", linked, *objects, target_object,
         "--as-needed", *libraries])
    run([native_tool, "link", "--in", linked, "--out", converted,
         "--stub-dir", sdk / "target/lib", "--module-sdk", "0x02000009",
         "--companion-sdk", "0x08050001", "--file-name", "eboot.elf"])

    package = out / TITLE
    if package.exists():
        shutil.rmtree(package)
    shutil.copytree(base_package, package)
    run([native_tool, "self", "--sign", "--in", converted, "--out",
         package / "eboot.bin", "--magic", "0x1D3D154F"])
    files = {str(path.relative_to(package)): sha(path)
             for path in sorted(package.rglob("*")) if path.is_file()}
    manifest = {"schema": "lapy-exit-target/1", "title": TITLE,
                "source_sha256": sha(source), "eboot_sha256": files["eboot.bin"],
                "files_sha256": files}
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"Built {package}\neboot_sha256={files['eboot.bin']}")


if __name__ == "__main__":
    main()
