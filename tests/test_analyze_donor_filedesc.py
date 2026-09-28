import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_donor_filedesc_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_donor_filedesc.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class DonorFiledescAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log, self.server = root / "donor.log", root / "server.json"
        self.build, self.elf = root / "build.json", root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "d" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "donor-filedesc-native-rfork-read-only",
            "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.cdir = 1
        self.held = 62
        self.ref_hint = 1
        self.write_run()

    def write_run(self):
        messages = [
            f"probe_start build={self.build_id} firmware=12020000 mode=donor-rfork-read-only",
            f"donor_sample build={self.build_id} phase=baseline hold=60 use=59",
            f"donor_identity build={self.build_id} distinct_fd=1 root_system=1 jail_null=1 cdir_system={self.cdir} ref_hint={self.ref_hint}",
            f"donor_sample build={self.build_id} phase=held hold={self.held} use={self.held - 1}",
            f"donor_sample build={self.build_id} phase=released hold=60 use=59",
            f"probe_result build={self.build_id} stage=complete error=0 cleanup_error=0 child_reaped=1",
        ]
        raw = ("HELLO ps5log/1 title=LAPYDON app=probe boot=0x1\n" +
               "".join(f"{i}\t{i}\tMARK\t{msg}\n" for i, msg in
                       enumerate(messages, 1)) +
               "BYE seq=6 reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYDON", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 6, "last_seq": 6}))

    def test_two_root_references_from_native_copy(self):
        result = analysis.analyze(self.log, self.server, self.build, self.elf)
        self.assertTrue(result["balanced"])
        self.assertEqual(result["native_root_references"], 2)

    def test_one_root_reference_without_root_cdir(self):
        self.cdir = 0
        self.held = 61
        self.write_run()
        self.assertEqual(analysis.analyze(self.log, self.server, self.build,
                                          self.elf)["native_root_references"], 1)

    def test_unbalanced_or_shared_donor_rejected(self):
        self.held = 61
        self.write_run()
        with self.assertRaisesRegex(ValueError, "not balanced"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.held = 62
        self.ref_hint = 2
        self.write_run()
        with self.assertRaisesRegex(ValueError, "private"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_incomplete_stream_and_wrong_elf_rejected(self):
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
