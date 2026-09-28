import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_target_dirs_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_target_dirs.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class TargetDirsAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log, self.server = root / "dirs.log", root / "server.json"
        self.build, self.elf = root / "build.json", root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "b" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "target-directory-read-only", "console_validated": False,
            "target_pid": 4242,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.result = (f"2\t2\tMARK\tprobe_result build={self.build_id} "
                       "target_pid=4242 stage=complete error=0 stable=1 "
                       "root_nonnull=1 jail_nonnull=0 root_jail_same=0 "
                       "system_known=1 root_system=0 jail_system=0")
        self.write_run()

    def write_run(self):
        reason = "probe-complete" if "error=0 " in self.result else "probe-failed"
        raw = ("HELLO ps5log/1 title=LAPYDIR app=probe boot=0x1\n" +
               f"1\t1\tMARK\tprobe_start build={self.build_id} "
               "firmware=12020000 target_pid=4242 mode=read-only\n" +
               self.result + f"\nBYE seq=2 reason={reason}\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYDIR", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 2, "last_seq": 2}))

    def test_null_jail_observation(self):
        result = analysis.analyze(self.log, self.server, self.build, self.elf)
        self.assertTrue(result["observed"])
        self.assertFalse(result["jail_nonnull"])

    def test_contradictory_identity_and_pid_rejected(self):
        self.result = self.result.replace("root_jail_same=0", "root_jail_same=1")
        self.write_run()
        with self.assertRaisesRegex(ValueError, "contradicts"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.result = self.result.replace("target_pid=4242", "target_pid=4243")
        self.write_run()
        with self.assertRaisesRegex(ValueError, "wrong probe result"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_failure_and_incomplete_stream(self):
        self.result = (f"2\t2\tERR\tprobe_result build={self.build_id} "
                       "target_pid=4242 stage=first_snapshot error=3 stable=0 "
                       "root_nonnull=0 jail_nonnull=0 root_jail_same=0 "
                       "system_known=0 root_system=0 jail_system=0")
        self.write_run()
        self.assertFalse(analysis.analyze(self.log, self.server, self.build,
                                          self.elf)["observed"])
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 1, "to": 2}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
