import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_cross_process_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_cross_process_directory.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class CrossProcessDirectoryAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log = root / "cross.log"
        self.server = root / "server.json"
        self.build = root / "build.json"
        self.elf = root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "c" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "cross-process-root-fd", "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.result = (f"probe_result build={self.build_id} stage=complete "
                       "error=0 child_error=0 parent_root_closed=1 "
                       "child_after_close=1 child_reaped=1")
        self.write_run()

    def write_run(self):
        raw = ("HELLO ps5log/1 title=LAPYXFD app=probe boot=0x1\n" +
               f"1\t1\tMARK\tprobe_start build={self.build_id} "
               "firmware=12020000 mode=cross-process-root-fd\n" +
               f"2\t2\tMARK\t{self.result}\n" +
               "BYE seq=2 reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYXFD", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 2, "last_seq": 2}))

    def test_requires_child_use_after_sender_close(self):
        self.assertTrue(analysis.analyze(self.log, self.server, self.build,
                                         self.elf)["supported"])
        self.result = self.result.replace("child_after_close=1",
                                          "child_after_close=0")
        self.write_run()
        with self.assertRaisesRegex(ValueError, "unproven"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_rejects_incomplete_stream_and_wrong_elf(self):
        server = json.loads(self.server.read_text())
        server["clean"] = False
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.write_run()
        self.elf.write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "identity"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
