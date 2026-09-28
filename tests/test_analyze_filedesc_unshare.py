import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_filedesc_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_filedesc_unshare.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class FileDescAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log = root / "unshare.log"
        self.server = root / "server.json"
        self.build = root / "build.json"
        self.elf = root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "a" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "self-filedesc-native-unshare", "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.start = (f"1\t1\tMARK\tprobe_start build={self.build_id} "
                      "firmware=00001202 mode=self-only scan_bytes=128")
        self.result = (f"2\t2\tMARK\tprobe_result build={self.build_id} "
                       "stage=wait_child error=0 candidate_count=1 ref_offset=0x42 "
                       "ref_width=2 initial_refs=1 shared_refs=2 "
                       "private_refs=1 old_refs=1 shared_same=1 private_new=1 "
                       "unshared=1")
        self.write_run()

    def write_run(self):
        reason = "probe-complete" if "error=0 " in self.result else "probe-failed"
        raw = ("HELLO ps5log/1 title=LAPYFD app=probe boot=0x1\n" +
               self.start + "\n" + self.result +
               f"\nBYE seq=2 reason={reason}\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYFD", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 2, "last_seq": 2}))

    def test_success_requires_full_native_transition(self):
        self.assertTrue(analysis.analyze(self.log, self.server, self.build,
                                         self.elf)["supported"])
        self.result = self.result.replace("old_refs=1", "old_refs=2")
        self.write_run()
        with self.assertRaisesRegex(ValueError, "contradicts"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_failure_is_reported_as_unsupported(self):
        self.result = self.result.replace("\tMARK\t", "\tERR\t").replace(
            "stage=wait_child error=0 ", "stage=native_unshare error=1 ")
        self.write_run()
        self.assertFalse(analysis.analyze(self.log, self.server, self.build,
                                          self.elf)["supported"])

    def test_incomplete_or_mismatched_artifact_is_rejected(self):
        data = json.loads(self.server.read_text())
        data["gaps"] = [{"from": 1, "to": 2}]
        self.server.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.write_run()
        self.elf.write_bytes(b"other ELF")
        with self.assertRaisesRegex(ValueError, "ELF hash"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
