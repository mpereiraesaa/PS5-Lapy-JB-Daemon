import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_root_analysis", Path(__file__).resolve().parents[1] / "tools/analyze_root_refs.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class RootAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log = root / "bounded.log"
        self.server = root / "server.json"
        self.build = root / "build.json"
        self.build_id = "a" * 64
        self.build.write_text(json.dumps({"build_id": self.build_id,
                                          "mode": "root-vnode-read-only",
                                          "console_validated": False}))
        self.records = [
            f"1\t1\tMARK\tprobe_start build={self.build_id} firmware=00001202 samples=2 period_us=1 mode=read-only",
            f"2\t2\tMARK\tcandidate_change build={self.build_id} sample=1 offset=0x1c0 before=44 after=42 delta=-2",
            f"3\t3\tMARK\tprobe_result build={self.build_id} stage=complete error=0 sampled=2 changes=1 expected=2",
        ]
        self.write_run()

    def write_run(self):
        data = ("HELLO ps5log/1 title=LAPYREF app=probe boot=0x1\n" +
                "\n".join(self.records) + "\nBYE seq=3 reason=probe-complete\n").encode()
        self.log.write_bytes(data)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYREF", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(data).hexdigest(),
            "records": 3, "last_seq": 3,
        }))

    def test_complete_observation(self):
        result = analysis.analyze(self.log, self.server, self.build)
        self.assertEqual(result["samples"], 2)
        self.assertEqual(result["candidates"], [{"offset": "0x1c0", "events": 1,
                                                  "net": -2, "negative": 1,
                                                  "positive": 0}])

    def test_incomplete_and_tampered_evidence_rejected(self):
        self.log.write_bytes(self.log.read_bytes() + b"junk")
        with self.assertRaisesRegex(ValueError, "hash"):
            analysis.analyze(self.log, self.server, self.build)
        self.write_run()
        data = json.loads(self.server.read_text())
        data["gaps"] = [{"from": 1, "to": 2}]
        self.server.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build)

    def test_bad_delta_rejected(self):
        self.records[1] = self.records[1].replace("delta=-2", "delta=-1")
        self.write_run()
        with self.assertRaisesRegex(ValueError, "outside probe contract"):
            analysis.analyze(self.log, self.server, self.build)


if __name__ == "__main__":
    unittest.main()
