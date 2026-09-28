import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_move_only_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_move_only.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class MoveOnlyAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log, self.server = root / "move.log", root / "server.json"
        self.build, self.elf = root / "build.json", root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "a" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "move-only-donor-reference-round-trip",
            "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.root_final = 60
        self.data_final = (4, 3)
        self.write_run()

    def write_run(self):
        ident = self.build_id
        def sample(phase, rh, ru, dh=5, du=4):
            known = int(phase != "baseline")
            if not known:
                dh = du = 0
            return (f"move_sample build={ident} phase={phase} "
                    f"root_hold={rh} root_use={ru} data_known={known} "
                    f"data_hold={dh} data_use={du}")
        def donor(role, cwd):
            return (f"donor_ready build={ident} role={role} private=1 "
                    f"root_system=1 jail_null=1 cwd_system={cwd} ref_hint=1")
        messages = [
            f"probe_start build={ident} firmware=12020000 mode=move-only-old-root-round-trip",
            sample("baseline", 60, 59),
            donor("data", 0),
            sample("data_acquired", 61, 60),
            donor("root", 1), donor("root", 1), donor("root", 1),
            sample("data_installed", 67, 66),
            sample("old_root_released", 63, 62),
            sample("root_restored", 63, 62),
            sample("baseline_restored", self.root_final,
                   self.root_final - 1, *self.data_final),
            f"probe_result build={ident} stage=complete error=0 first=1 second=1 root_balanced=1 data_released=1 all_reaped=1",
        ]
        raw = ("HELLO ps5log/1 title=LAPYMOVE app=probe boot=0x1\n" +
               "".join(f"{i}\t{i}\tMARK\t{message}\n" for i, message in
                       enumerate(messages, 1)) +
               "BYE seq=12 reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYMOVE", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 12, "last_seq": 12}))

    def test_balanced_move_only_round_trip(self):
        self.assertTrue(analysis.analyze(self.log, self.server, self.build,
                                         self.elf)["balanced"])

    def test_root_or_data_drift_rejected(self):
        self.root_final = 61
        self.write_run()
        with self.assertRaisesRegex(ValueError, "root count drift"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.root_final = 60
        self.data_final = (5, 4)
        self.write_run()
        with self.assertRaisesRegex(ValueError, "not released"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_stream_and_elf_identity_required(self):
        self.elf.write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "ELF identity"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.elf.write_bytes(b"\x7fELFsample")
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 3, "to": 4}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
