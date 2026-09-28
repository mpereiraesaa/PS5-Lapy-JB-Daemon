"""Build a bounded PS5 native capability probe; never deploy it."""
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
    parser.add_argument("--exclusive-receiver", action="store_true",
                        help="test explicit CLOEXEC setup in this non-execing probe only")
    parser.add_argument("--probe", choices=("transport", "cross-process-directory", "credentials", "vfs", "cross-root", "sysent", "root-refs", "root-native-refs", "kernel-symbols", "filedesc-unshare", "target-dirs", "request-dirs", "donor-filedesc", "null-jail-transfer", "old-root-release", "ptrace-quiescence", "signal-quiescence", "move-only"), default="transport")
    parser.add_argument("--target-pid", type=int,
                        help="live process PID to observe; required only for target-dirs")
    parser.add_argument("--sony-privileges", action="store_true",
                        help="temporarily change Sony fields after native credential replacement, cross-root probe only")
    parser.add_argument("--root-identity", action="store_true",
                        help="native setgid/setuid(0) in the disposable cross-root probe before the Sony scope")
    parser.add_argument("--cwd-root", action="store_true",
                        help="retain original root as cwd; do not open root/cwd descriptors in cross-root probe")
    args = parser.parse_args()
    if args.probe != "transport" and args.exclusive_receiver:
        parser.error("--exclusive-receiver requires --probe transport")
    if args.sony_privileges and args.probe != "cross-root":
        parser.error("--sony-privileges requires --probe cross-root")
    if args.root_identity and args.probe != "cross-root":
        parser.error("--root-identity requires --probe cross-root")
    if args.cwd_root and args.probe != "cross-root":
        parser.error("--cwd-root requires --probe cross-root")
    if args.probe == "target-dirs":
        if args.target_pid is None or not 2 <= args.target_pid <= 2147483647:
            parser.error("--target-dirs requires a positive 32-bit --target-pid")
    elif args.target_pid is not None:
        parser.error("--target-pid requires --probe target-dirs")
    sdk = Path(args.sdk).resolve()
    logging = args.logging_client.resolve()
    names = {"transport": ("native_probe.c", "native_directory.c", "native_directory.h"),
             "cross-process-directory": ("cross_process_directory_probe.c", "native_directory.c", "native_directory.h"),
             "credentials": ("credential_probe.c",),
             "vfs": ("vfs_probe.c", "native_vfs_syscall.h"),
             "cross-root": ("cross_root_probe.c", "native_vfs_syscall.h", "vfs_prerequisites.h",
             "sony_scope.c", "sony_scope.h"), "sysent": ("sysent_probe.c",),
             "root-refs": ("root_reference_probe.c",),
             "root-native-refs": ("root_native_reference_probe.c",),
             "kernel-symbols": ("kernel_symbol_probe.c",),
             "filedesc-unshare": ("filedesc_unshare_probe.c", "filedesc_refcount.c",
                                  "filedesc_refcount.h"),
             "target-dirs": ("target_directory_probe.c",),
             "request-dirs": ("request_directory_probe.c",),
             "donor-filedesc": ("donor_filedesc_probe.c",),
             "null-jail-transfer": ("donor_null_jail_transfer_probe.c",),
             "old-root-release": ("donor_old_root_probe.c",),
             "ptrace-quiescence": ("ptrace_quiescence_probe.c",),
             "signal-quiescence": ("signal_quiescence_probe.c",),
             "move-only": ("donor_move_only_probe.c", "donor_transaction.c",
                           "donor_transaction.h")}[args.probe]
    files = [ROOT / "source" / name for name in names]
    inputs = {str(p.relative_to(ROOT)): sha(p) for p in files}
    inputs["external/ps5log.h"] = sha(logging / "ps5log.h")
    inputs["tools/build_probe.py"] = sha(Path(__file__).resolve())
    sdk_inputs = {str(p.relative_to(sdk)): sha(p)
                  for p in sorted((sdk / "target").rglob("*")) if p.is_file()}
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    if args.probe in ("ptrace-quiescence", "signal-quiescence"):
        flags.append("-pthread")
    if args.exclusive_receiver:
        flags.append("-DLAPY_PROBE_EXCLUSIVE=1")
    if args.sony_privileges:
        flags.append("-DLAPY_PROBE_SONY=1")
    if args.root_identity:
        flags.append("-DLAPY_PROBE_ROOT_IDENTITY=1")
    if args.cwd_root:
        flags.append("-DLAPY_PROBE_CWD_ROOT=1")
    if args.target_pid is not None:
        flags.append(f"-DLAPY_TARGET_PID={args.target_pid}")
    identity = hashlib.sha256(json.dumps({"inputs": inputs, "sdk": sdk_inputs,
                                         "flags": flags}, sort_keys=True).encode()).hexdigest()
    stem = {"transport": "native", "credentials": "credential", "vfs": "vfs",
            "cross-process-directory": "cross_process_directory",
            "cross-root": "cross_root", "sysent": "sysent",
            "root-refs": "root_refs", "kernel-symbols": "kernel_symbols",
            "root-native-refs": "root_native_refs",
            "filedesc-unshare": "filedesc_unshare",
            "target-dirs": "target_dirs", "request-dirs": "request_dirs",
            "donor-filedesc": "donor_filedesc",
            "null-jail-transfer": "null_jail_transfer",
            "old-root-release": "old_root_release",
            "ptrace-quiescence": "ptrace_quiescence",
            "signal-quiescence": "signal_quiescence",
            "move-only": "move_only"}[args.probe]
    output = ROOT / ("build/probe" if args.probe == "transport" else
                     f"build/{stem}-probe/pid-{args.target_pid}" if args.probe == "target-dirs" else
                     f"build/{stem}-probe")
    output.mkdir(parents=True, exist_ok=True)
    header = output / "probe_identity.h"
    header.write_text('#define LAPY_PROBE_ID "' + identity + '"\n')
    elf = output / f"lapy_{stem}_probe.elf"
    manifest = output / "manifest.json"
    elf.unlink(missing_ok=True)
    manifest.unlink(missing_ok=True)
    command = [str(sdk / "bin/prospero-clang"), *flags, "-I" + str(logging),
               "-I" + str(output), "-I" + str(ROOT / "source"),
               *[str(p) for p in files if p.suffix == ".c"], "-o", str(elf)]
    with (output / "build.log").open("w") as log:
        log.write(json.dumps(command) + "\n")
        log.flush()
        subprocess.run(command, check=True, stdout=log, stderr=log)
    if elf.read_bytes()[:4] != b"\x7fELF":
        raise RuntimeError("Output is not ELF")
    manifest.write_text(json.dumps({"schema": "lapy-probe-build/1", "build_id": identity,
                                   "inputs_sha256": inputs, "sdk_inputs_sha256": sdk_inputs,
                                   "elf_sha256": sha(elf),
                                   "mode": {"transport": "transport-only",
                                            "cross-process-directory": "cross-process-root-fd",
                                            "credentials": "same-euid",
                                            "vfs": "existing-root", "cross-root": "cross-root",
                                            "sysent": "sysent-read-only",
                                            "root-refs": "root-vnode-read-only",
                                            "root-native-refs": "root-vnode-native-open-close",
                                            "kernel-symbols": "kernel-symbol-lookup-only",
                                            "filedesc-unshare": "self-filedesc-native-unshare",
                                            "target-dirs": "target-directory-read-only",
                                            "request-dirs": "live-request-directory-read-only",
                                            "donor-filedesc": "donor-filedesc-native-rfork-read-only",
                                            "null-jail-transfer": "null-jail-two-donor-pointer-transfer",
                                            "old-root-release": "old-root-native-donor-release",
                                            "ptrace-quiescence": "disposable-multithread-ptrace-quiescence",
                                            "signal-quiescence": "disposable-multithread-signal-quiescence",
                                            "move-only": "move-only-donor-reference-round-trip"}[args.probe],
                                   "receiver": ("exclusive" if args.exclusive_receiver else "atomic")
                                               if args.probe == "transport" else None,
                                   "target_pid": args.target_pid if args.probe == "target-dirs" else None,
                                   "console_validated": False}, indent=2, sort_keys=True) + "\n")
    print(f"Built {elf.relative_to(ROOT)}\nbuild_id={identity}\nsha256={sha(elf)}")


if __name__ == "__main__":
    main()
