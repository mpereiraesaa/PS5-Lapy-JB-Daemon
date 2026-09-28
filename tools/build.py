"""Build an explicitly selected legacy comparison artifact from pinned source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HIJACKER_URL = "https://github.com/illusion0001/libhijacker.git"
HIJACKER_REV = "f1ac64ad97c1f3b2fbcb73a9e43832b5fbdeb23e"
SOURCES = ("hijacker.cpp", "kernel.cpp", "dbg.cpp", "print.cpp", "backtrace.cpp")


def run(argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True, stderr=subprocess.STDOUT)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_dependency(path, revision=HIJACKER_REV):
    if run(["git", "rev-parse", "HEAD"], path).strip() != revision:
        raise ValueError("Dependency revision mismatch; existing checkout left untouched")
    if run(["git", "status", "--porcelain", "--untracked-files=all", "--ignored"], path).strip():
        raise ValueError("Dependency checkout is not clean; refusing a non-pinned build")


def stage_headers(dependency, destination):
    shutil.copytree(dependency / "include", destination, dirs_exist_ok=True)
    header = destination / "kernel/proc.hpp"
    original = "extern const uintptr_t kernel_base;"
    text = header.read_text()
    if text.count(original) != 1:
        raise ValueError("kernel_base compatibility declaration did not match exactly")
    # Lapy initializes this variable from payload_args at runtime. This changes
    # a declaration only; the pinned dependency checkout is never patched.
    header.write_text(text.replace(original, "extern uintptr_t kernel_base;"))


def build(args):
    if not args.legacy:
        raise ValueError("Native reference-safe backend unavailable. --legacy is for offline comparison only")
    if not args.sdk:
        raise ValueError("Set PS5_PAYLOAD_SDK or pass --sdk")
    sdk = Path(args.sdk).resolve()
    compiler = sdk / "bin/prospero-clang++"
    if not compiler.is_file() or not (sdk / "target/lib/crt1.o").is_file():
        raise ValueError("SDK must contain bin/prospero-clang++ and target/lib/crt1.o")
    runtime = Path(args.cxxrt).resolve() / "lib" if args.cxxrt else sdk / "target/lib"
    libraries = [runtime / (name + ".a") for name in ("libc++", "libc++abi", "libunwind")]
    if any(not path.is_file() for path in libraries):
        raise ValueError("Missing PS5 C++ runtime archives; set PS5_CXXRT to their parent directory")
    dependency = ROOT / ".deps/libhijacker"
    if not dependency.exists():
        if not args.fetch_deps:
            raise ValueError("Pinned dependency missing; use --fetch-deps")
        dependency.parent.mkdir(exist_ok=True)
        run(["git", "clone", "--no-checkout", HIJACKER_URL, str(dependency)])
        run(["git", "checkout", "--detach", HIJACKER_REV], dependency)
    verify_dependency(dependency)
    output = ROOT / "build/legacy"
    output.mkdir(parents=True, exist_ok=True)
    elf = output / "lapy_jb_daemon_legacy.elf"
    manifest = output / "manifest.json"
    elf.unlink(missing_ok=True)
    manifest.unlink(missing_ok=True)
    headers = output / "include"
    if headers.exists():
        shutil.rmtree(headers)
    stage_headers(dependency, headers)
    flags = ["-std=c++20", "-O2", "-fno-rtti", "-fno-exceptions",
             "-ffunction-sections", "-fdata-sections", "-isystem", str(headers)]
    sources = [ROOT / "source/main.cpp", ROOT / "source/offsets_v940.cpp"]
    sources += [dependency / "libhijacker/source" / name for name in SOURCES]
    objects = []
    print("Building LEGACY comparison only: vnode references and shared credentials remain unfixed.")
    with (output / "build.log").open("w") as log:
        for source in sources:
            obj = output / (source.stem + ".o")
            command = [str(compiler), *flags, "-c", str(source), "-o", str(obj)]
            log.write(json.dumps(command) + "\n")
            log.flush()
            result = subprocess.run(command, stdout=log, stderr=log)
            if result.returncode:
                raise ValueError("Compilation failed; see build/legacy/build.log")
            objects.append(obj)
        command = [str(compiler), *flags, "-Wl,--gc-sections", "-L" + str(runtime),
                   "-o", str(elf), *map(str, objects), "-lkernel_sys", "-lSceNotification"]
        log.write(json.dumps(command) + "\n")
        log.flush()
        if subprocess.run(command, stdout=log, stderr=log).returncode:
            elf.unlink(missing_ok=True)
            raise ValueError("Link failed; see build/legacy/build.log")
    if elf.read_bytes()[:4] != b"\x7fELF":
        raise ValueError("Link output is not ELF")
    inputs = sources + sorted(headers.rglob("*.hpp")) + sorted(headers.rglob("*.h"))
    inputs += [ROOT / "tools/build.py"]
    record = {
        "schema": "lapy-build/1", "variant": "legacy-unsafe",
        "native_reference_backend": False, "console_validated": False,
        "source_revision": run(["git", "rev-parse", "HEAD"], ROOT).strip(),
        "source_dirty": bool(run(["git", "status", "--porcelain"], ROOT).strip()),
        "dependency": {"url": HIJACKER_URL, "revision": HIJACKER_REV},
        "header_adjustment": "kernel_base declaration: const uintptr_t -> uintptr_t",
        "compiler_version": run([str(compiler), "--version"]).strip(),
        "inputs_sha256": {str(p.relative_to(ROOT)): digest(p) for p in inputs},
        "sdk_inputs_sha256": {str(p.relative_to(sdk)): digest(p)
                              for p in sorted((sdk / "target").rglob("*")) if p.is_file()},
        "runtime_sha256": {p.name: digest(p) for p in libraries},
        "elf": elf.name, "elf_sha256": digest(elf),
    }
    manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Built {elf.relative_to(ROOT)}\nSHA256 {record['elf_sha256']}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--fetch-deps", action="store_true")
    parser.add_argument("--sdk", default=os.environ.get("PS5_PAYLOAD_SDK"))
    parser.add_argument("--cxxrt", default=os.environ.get("PS5_CXXRT"))
    args = parser.parse_args(argv)
    try:
        build(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Build refused: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.output:
            print(error.output, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
