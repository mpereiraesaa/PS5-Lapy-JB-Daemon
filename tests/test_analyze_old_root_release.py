import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_old_root_release_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_old_root_release.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class OldRootReleaseAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log, self.server = root / "old.log", root / "server.json"
        self.build, self.elf = root / "build.json", root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "f" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "old-root-native-donor-release",
            "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.final_data = (4, 3)
        self.old_donor_root = 61
        self.write_run()

    def write_run(self):
        ident = self.build_id
        def sample(phase, rh, ru, dh=5, du=4):
            known = 0 if phase == "baseline" else 1
            if not known:
                dh = du = 0
            return (f"old_root_sample build={ident} phase={phase} "
                    f"root_hold={rh} root_use={ru} data_known={known} "
                    f"data_hold={dh} data_use={du}")
        messages = [
            f"probe_start build={ident} firmware=12020000 mode=donor-old-root-release",
            f"target_ready build={ident} private=1 root_system=1 jail_null=1 cdir_system=1 ref_hint=1",
            sample("baseline", 60, 59),
            f"donor_ready build={ident} role=old private=1 root_system=1 jail_null=1 cdir_system=0 ref_hint=1",
            sample("data_acquired", 61, 60),
            f"donor_ready build={ident} role=replacement private=1 root_system=1 jail_null=1 cdir_system=1 ref_hint=1",
            sample("both_held", 63, 62),
            sample("old_root_placed", 63, 62),
            sample("old_donor_released", self.old_donor_root,
                   self.old_donor_root - 1),
            sample("root_restored", 61, 60),
            sample("baseline_restored", 60, 59, *self.final_data),
            f"probe_result build={ident} stage=complete error=0 old_reaped=1 replacement_reaped=1",
        ]
        raw = ("HELLO ps5log/1 title=LAPYOLD app=probe boot=0x1\n" +
               "".join(f"{i}\t{i}\tMARK\t{msg}\n" for i, msg in
                       enumerate(messages, 1)) +
               "BYE seq=12 reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYOLD", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 12, "last_seq": 12}))

    def test_balanced_old_root_release(self):
        self.assertTrue(analysis.analyze(self.log, self.server, self.build,
                                         self.elf)["balanced"])

    def test_missing_old_release_or_wrong_root_count_rejected(self):
        self.final_data = (5, 4)
        self.write_run()
        with self.assertRaisesRegex(ValueError, "not released"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.final_data = (4, 3)
        self.old_donor_root = 62
        self.write_run()
        with self.assertRaisesRegex(ValueError, "not balanced"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_incomplete_stream_or_wrong_elf_rejected(self):
        self.elf.write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "ELF identity"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.elf.write_bytes(b"\x7fELFsample")
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 2, "to": 3}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
