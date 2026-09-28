import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_request_directory_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_request_directory.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class RequestDirectoryAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log, self.server = root / "request.log", root / "server.json"
        self.build, self.elf = root / "build.json", root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "c" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "live-request-directory-read-only", "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.result = (f"2\t2\tMARK\tprobe_result build={self.build_id} "
                       "stage=complete error=0 polls=4 target_pid=4242 "
                       "stable=1 acknowledged=1 root_null=0 root_system=0 "
                       "jail_null=0 jail_system=0 root_jail_same=1 "
                       "ref_hint=1 ref_hint_valid=1")
        self.write_run()

    def write_run(self):
        reason = "probe-complete" if "error=0 " in self.result else "probe-failed"
        raw = ("HELLO ps5log/1 title=LAPYREQ app=probe boot=0x1\n" +
               f"1\t1\tMARK\tprobe_start build={self.build_id} "
               "firmware=12020000 mode=request-read-only max_polls=600\n" +
               self.result + f"\nBYE seq=2 reason={reason}\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYREQ", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 2, "last_seq": 2}))

    def test_private_target_directory_observation(self):
        result = analysis.analyze(self.log, self.server, self.build, self.elf)
        self.assertTrue(result["observed"])
        self.assertFalse(result["jail_null"])
        self.assertEqual(result["filedesc_ref_hint"], 1)

    def test_null_jail_observation(self):
        self.result = self.result.replace("jail_null=0", "jail_null=1")
        self.result = self.result.replace("root_jail_same=1", "root_jail_same=0")
        self.write_run()
        self.assertTrue(analysis.analyze(self.log, self.server, self.build,
                                         self.elf)["jail_null"])

    def test_invalid_identity_rejected(self):
        self.result = self.result.replace("jail_null=0", "jail_null=1")
        self.write_run()
        with self.assertRaisesRegex(ValueError, "contradicts"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 1, "to": 2}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_timeout_is_complete_failure_stream(self):
        self.result = (f"2\t2\tERR\tprobe_result build={self.build_id} "
                       "stage=find_request error=60 polls=600 target_pid=-1 "
                       "stable=0 acknowledged=0 root_null=0 root_system=0 "
                       "jail_null=0 jail_system=0 root_jail_same=0 "
                       "ref_hint=0 ref_hint_valid=0")
        self.write_run()
        self.assertFalse(analysis.analyze(self.log, self.server, self.build,
                                          self.elf)["observed"])


if __name__ == "__main__":
    unittest.main()
