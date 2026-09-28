import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_nonroot_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_retained_nonroot.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class NonrootAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log = root / "two.log"
        self.server = root / "server.json"
        self.build = root / "build.json"
        self.elf = root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFtwo")
        self.identity = "a" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.identity,
            "mode": "disposable-nonroot-old-release",
            "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.final_hold = 60
        self.first_release_data_hold = 2
        self.complete = True
        self.write_run()

    def write_run(self):
        ident = self.identity
        def sample(phase, root_delta, data_delta):
            root_hold = self.final_hold if phase == "target_reaped" else 60 + root_delta
            data_hold = (self.first_release_data_hold if phase == "first_reaped"
                         else 2 + data_delta)
            return (f"vnode_sample build={ident} phase={phase} "
                    f"root_hold={root_hold} root_use={root_hold - 1} "
                    f"data_hold={data_hold} data_use={data_hold}")
        messages = [
            f"probe_start build={ident} firmware=12020000 mode=retained-nonroot-old",
            sample("baseline", 0, 0), sample("target_ready", 1, 1),
            f"target_ready build={ident} pid=10 threads=2 private=1 root_system=1 jail_null=1 cwd_data=1 hold_seconds=12",
            f"target_stopped build={ident} pid=10 threads=2 suspended=2",
            sample("first_ready", 3, 1),
            sample("nonroot_prepositioned", 3, 1),
            f"nonroot_prepositioned build={ident} target_root_data=1 target_cwd_system=1 first_receiver_null=1",
            sample("donors_ready", 5, 1),
            sample("transfer_committed", 5, 1),
            f"transfer_committed build={ident} target_stopped=1 target_root_system=1 target_jail_system=1 first_old_data_received=1 donor_roots_null=1",
            sample("first_reaped", 4, 0), sample("second_reaped", 3, 0),
            sample("target_reaped", 0, 0),
            f"probe_result build={ident} stage=complete error=0 moved=1 first_reaped=1 second_reaped=1 target_reaped={int(self.complete)} intermediate_noise=0",
        ]
        raw = ("HELLO ps5log/1 title=LAPYNROOT app=probe boot=0x1\n" +
               "".join(f"{i}\t{i}\tMARK\t{msg}\n" for i, msg in
                       enumerate(messages, 1)) +
               f"BYE seq={len(messages)} reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYNROOT", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": len(messages), "last_seq": len(messages)}))

    def test_balanced_native_exit(self):
        result = analysis.analyze(self.log, self.server, self.build, self.elf)
        self.assertTrue(result["balanced"])
        self.assertEqual(result["root_baseline_hold"], 60)
        self.assertEqual(result["data_baseline_hold"], 2)

    def test_missing_release_rejected(self):
        self.final_hold = 61
        self.write_run()
        with self.assertRaisesRegex(ValueError, "not balanced"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.final_hold = 60
        self.complete = False
        self.write_run()
        with self.assertRaisesRegex(ValueError, "cleanup incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_distinct_old_root_release_required(self):
        self.first_release_data_hold = 3
        self.write_run()
        with self.assertRaisesRegex(ValueError, "old data reference"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_artifact_and_stream_integrity(self):
        self.elf.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "ELF identity"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.elf.write_bytes(b"\x7fELFtwo")
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 2, "to": 3}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
