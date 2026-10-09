"""Build a bounded PS5 native capability probe; never deploy it."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", default=os.environ.get("PS5_PAYLOAD_SDK"), required=not os.environ.get("PS5_PAYLOAD_SDK"))
    parser.add_argument("--logging-client", type=Path, required=True)
    parser.add_argument("--log-server",
                        help="embed a dotted-IPv4 ps5log receiver instead of reading dev.conf")
    parser.add_argument("--result-file",
                        help="also mirror probe records to this absolute console path")
    parser.add_argument("--exclusive-receiver", action="store_true",
                        help="test explicit CLOEXEC setup in this non-execing probe only")
    parser.add_argument("--probe", choices=("transport", "cross-process-directory", "credentials", "vfs", "cross-root", "sysent", "root-refs", "root-native-refs", "kernel-symbols", "filedesc-unshare", "target-dirs", "request-dirs", "donor-filedesc", "null-jail-transfer", "old-root-release", "ptrace-quiescence", "signal-quiescence", "thread-stop-calibration", "live-target-stop", "live-target-ptrace", "debug-retention", "move-only", "retained-cross-process", "retained-two-root", "retained-nonroot", "remote-credential-clone", "self-ptrace-clone", "preentry-log"), default="transport")
    parser.add_argument("--target-pid", type=int,
                        help="live process PID to observe; required only for target-dirs")
    parser.add_argument("--target-title",
                        help="PPSA title to observe; valid for live-target-stop/ptrace")
    parser.add_argument("--observe-state", action="store_true",
                        help="read stopped title root/jail/cwd and credential state; live-target-stop only")
    parser.add_argument("--self-stop", action="store_true",
                        help="locally SIGSTOP disposable target; retained-nonroot only")
    parser.add_argument("--scan-gadget", action="store_true",
                        help="read-only scan near retained title RIP; live-target-ptrace only")
    parser.add_argument("--exit-lifetime", action="store_true",
                        help="kill the stopped title and observe proc pointer invalidation; live-target-ptrace only")
    parser.add_argument("--sony-privileges", action="store_true",
                        help="temporarily change Sony fields after native credential replacement, cross-root probe only")
    parser.add_argument("--root-identity", action="store_true",
                        help="native setgid/setuid(0) in the disposable cross-root probe before the Sony scope")
    parser.add_argument("--cwd-root", action="store_true",
                        help="retain original root as cwd; do not open root/cwd descriptors in cross-root probe")
    args = parser.parse_args()
    if args.log_server is not None:
        try:
            ipaddress.IPv4Address(args.log_server)
        except ipaddress.AddressValueError:
            parser.error("--log-server must be a dotted IPv4 address")
    if args.result_file is not None:
        if args.probe != "live-target-ptrace" or not args.exit_lifetime:
            parser.error("--result-file requires the exit-lifetime probe")
        if not args.result_file.startswith("/data/") or any(
                part in ("", ".", "..") for part in args.result_file[6:].split("/")):
            parser.error("--result-file must be a normalized absolute path below /data")
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
    if args.target_title is not None:
        if args.probe not in ("live-target-stop", "live-target-ptrace") or not re.fullmatch(r"PPSA[0-9]{5}", args.target_title):
            parser.error("--target-title requires a live-target probe and a PPSA title ID")
    if args.observe_state and args.probe != "live-target-stop":
        parser.error("--observe-state requires --probe live-target-stop")
    if args.self_stop and args.probe != "retained-nonroot":
        parser.error("--self-stop requires --probe retained-nonroot")
    if args.scan_gadget and args.probe != "live-target-ptrace":
        parser.error("--scan-gadget requires --probe live-target-ptrace")
    if args.exit_lifetime and args.probe != "live-target-ptrace":
        parser.error("--exit-lifetime requires --probe live-target-ptrace")
    if args.exit_lifetime and args.scan_gadget:
        parser.error("--exit-lifetime and --scan-gadget are mutually exclusive")
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
             "thread-stop-calibration": ("thread_stop_calibration_probe.c",),
             "live-target-stop": ("live_target_stop_probe.c",),
             "live-target-ptrace": ("live_target_ptrace_probe.c",),
             "debug-retention": ("debug_retention_probe.c",),
             "move-only": ("donor_move_only_probe.c", "donor_transaction.c",
                           "donor_transaction.h"),
             "retained-cross-process": ("retained_cross_process_probe.c",
                                        "donor_transaction.c",
                                        "donor_transaction.h"),
             "retained-two-root": ("retained_two_root_probe.c",
                                    "donor_transaction.c",
                                    "donor_transaction.h"),
             "retained-nonroot": ("retained_nonroot_probe.c",
                                  "donor_transaction.c",
                                  "donor_transaction.h"),
             "remote-credential-clone": ("remote_credential_probe.c",),
             "self-ptrace-clone": ("self_ptrace_clone_probe.c",),
             "preentry-log": ("preentry_log_probe.c",)}[args.probe]
    files = [ROOT / "source" / name for name in names]
    inputs = {str(p.relative_to(ROOT)): sha(p) for p in files}
    inputs["external/ps5log.h"] = sha(logging / "ps5log.h")
    inputs["tools/build_probe.py"] = sha(Path(__file__).resolve())
    sdk_inputs = {str(p.relative_to(sdk)): sha(p)
                  for p in sorted((sdk / "target").rglob("*")) if p.is_file()}
    log_stub_source = sdk.parent / "sce_stubs/libkernel_sys.c"
    if args.probe == "preentry-log":
        if not log_stub_source.is_file():
            raise FileNotFoundError(log_stub_source)
        sdk_inputs["sdk-source/sce_stubs/libkernel_sys.c"] = sha(log_stub_source)
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    if args.probe in ("ptrace-quiescence", "signal-quiescence", "thread-stop-calibration", "debug-retention", "retained-cross-process", "retained-two-root", "retained-nonroot"):
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
    if args.target_title is not None:
        flags.append(f'-DLAPY_TARGET_TITLE="{args.target_title}"')
    if args.observe_state:
        flags.append("-DLAPY_OBSERVE_STATE=1")
    if args.self_stop:
        flags.append("-DLAPY_SELF_STOP=1")
    if args.scan_gadget:
        flags.append("-DLAPY_SCAN_GADGET=1")
    if args.exit_lifetime:
        flags.append("-DLAPY_EXIT_LIFETIME=1")
    if args.log_server is not None:
        flags.append(f'-DLAPY_LOG_SERVER="{args.log_server}"')
    if args.result_file is not None:
        flags.append(f'-DLAPY_RESULT_FILE="{args.result_file}"')
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
            "thread-stop-calibration": "thread_stop_calibration",
            "live-target-stop": "live_target_stop",
            "live-target-ptrace": "live_target_ptrace",
            "debug-retention": "debug_retention",
            "move-only": "move_only",
            "retained-cross-process": "retained_cross_process",
            "retained-two-root": "retained_two_root",
            "retained-nonroot": "retained_nonroot",
            "remote-credential-clone": "remote_credential_clone",
            "self-ptrace-clone": "self_ptrace_clone",
            "preentry-log": "preentry_log"}[args.probe]
    output = ROOT / ("build/probe" if args.probe == "transport" else
                     f"build/{stem}-probe/pid-{args.target_pid}" if args.probe == "target-dirs" else
                     f"build/{stem}-probe/{args.target_title}/state" if args.probe == "live-target-stop" and args.target_title and args.observe_state else
                     f"build/{stem}-probe/{args.target_title}" if args.probe == "live-target-stop" and args.target_title else
                     f"build/{stem}-probe/{args.target_title}/exit-lifetime" if args.probe == "live-target-ptrace" and args.target_title and args.exit_lifetime else
                     f"build/{stem}-probe/{args.target_title}/scan" if args.probe == "live-target-ptrace" and args.target_title and args.scan_gadget else
                     f"build/{stem}-probe/{args.target_title}" if args.probe == "live-target-ptrace" and args.target_title else
                     f"build/{stem}-probe/self-stop" if args.probe == "retained-nonroot" and args.self_stop else
                     f"build/{stem}-probe")
    output.mkdir(parents=True, exist_ok=True)
    header = output / "probe_identity.h"
    header.write_text('#define LAPY_PROBE_ID "' + identity + '"\n')
    elf = output / f"lapy_{stem}_probe.elf"
    manifest = output / "manifest.json"
    elf.unlink(missing_ok=True)
    manifest.unlink(missing_ok=True)
    extra_link = []
    if args.probe == "preentry-log":
        nid_source = output / "log_buffer_nid.c"
        nid_source.write_text(
            'asm(".global \\"C49jelxiaVE\\"\\n"\n'
            '    ".type \\"C49jelxiaVE\\" @function\\n"\n'
            '    "\\"C49jelxiaVE\\":\\n");\n')
        stub_so = output / "libkernel_sys_log_ext.so"
        stub_command = [str(sdk / "bin/prospero-clang"), "-shared",
                        "-Wl,-soname=libkernel_sys.sprx",
                        "-Wl,--unresolved-symbols=ignore-all", "-o",
                        str(stub_so), str(log_stub_source), str(nid_source)]
        subprocess.run(stub_command, check=True, stdout=subprocess.DEVNULL)
        extra_link = [str(stub_so), "-Wl,--allow-shlib-undefined"]
    command = [str(sdk / "bin/prospero-clang"), *flags, "-I" + str(logging),
               "-I" + str(output), "-I" + str(ROOT / "source"),
               *[str(p) for p in files if p.suffix == ".c"],
               *extra_link, "-o", str(elf)]
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
                                            "thread-stop-calibration": "disposable-thread-and-stop-field-calibration",
                                            "live-target-stop": "live-title-signal-stop-read-only",
                                            "live-target-ptrace": "live-title-exit-lifetime-read-only" if args.exit_lifetime else "live-title-ptrace-retention-read-only",
                                            "debug-retention": "disposable-debug-retention-child",
                                            "move-only": "move-only-donor-reference-round-trip",
                                            "retained-cross-process": "disposable-retained-cross-process-ref-transfer",
                                            "retained-two-root": "disposable-two-root-and-old-root-release",
                                            "retained-nonroot": "disposable-nonroot-old-release",
                                            "remote-credential-clone": "disposable-remote-native-credential-clone",
                                            "self-ptrace-clone": "disposable-payload-ptrace-native-clone",
                                            "preentry-log": "read-only-preentry-system-log-snapshot"}[args.probe],
                                   "receiver": ("exclusive" if args.exclusive_receiver else "atomic")
                                               if args.probe == "transport" else None,
                                   "target_pid": args.target_pid if args.probe == "target-dirs" else None,
                                   "target_title": args.target_title if args.probe in ("live-target-stop", "live-target-ptrace") else None,
                                   "observe_state": args.observe_state if args.probe == "live-target-stop" else None,
                                   "self_stop": args.self_stop if args.probe == "retained-nonroot" else None,
                                   "scan_gadget": args.scan_gadget if args.probe == "live-target-ptrace" else None,
                                    "exit_lifetime": args.exit_lifetime if args.probe == "live-target-ptrace" else None,
                                    "log_server": args.log_server,
                                    "result_file": args.result_file,
                                    "console_validated": False}, indent=2, sort_keys=True) + "\n")
    print(f"Built {elf.relative_to(ROOT)}\nbuild_id={identity}\nsha256={sha(elf)}")


if __name__ == "__main__":
    main()
