import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_live_state_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_live_target_state.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class LiveTargetStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log, self.server = root / "state.log", root / "server.json"
        self.build, self.elf = root / "build.json", root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFstate")
        self.identity = "b" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.identity,
            "mode": "live-title-signal-stop-read-only",
            "target_title": "PPSA99994", "observe_state": True,
            "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.jail_null = 1
        self.private_fd = 1
        self.write_run()

    def write_run(self):
        ident = self.identity
        messages = [
            f"probe_start build={ident} firmware=12020000 mode=live-title-stop-read-only title=PPSA99994 observe_state=1 max_polls=600",
            f"target_state build={ident} title=PPSA99994 root_null=0 root_system=0 jail_null={self.jail_null} jail_system=0 cwd_null=0 cwd_system=0 root_jail_same=0 cwd_root_same=1 uid_root=0 ruid_root=0 svuid_root=0 rgid_root=0 prison0=0 system_authid=0 full_caps=0 attrs80=0 credential_stable=1",
            f"probe_result build={ident} stage=complete error=0 polls=16 stop_polls=0 target_pid=1141 stop_sent=1 resume_sent=1 acknowledged=1 threads=1 suspended=1 stable_stop=1 private_fd={self.private_fd}",
        ]
        raw = ("HELLO ps5log/1 title=LAPYTS app=probe boot=0x1\n" +
               "".join(f"{i}\t{i}\tMARK\t{message}\n" for i, message in
                       enumerate(messages, 1)) +
               "BYE seq=3 reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYTS", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 3, "last_seq": 3}))

    def test_private_stable_prestate(self):
        result = analysis.analyze(self.log, self.server, self.build, self.elf)
        self.assertTrue(result["stopped_and_resumed"])
        self.assertEqual(result["jail_null"], 1)

    def test_shared_filedesc_or_contradictory_state_rejected(self):
        self.private_fd = 0
        self.write_run()
        with self.assertRaisesRegex(ValueError, "privately stopped"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.private_fd = 1
        self.write_run()
        raw = self.log.read_text().replace("jail_system=0", "jail_system=1")
        self.log.write_text(raw)
        server = json.loads(self.server.read_text())
        server["sha256"] = hashlib.sha256(raw.encode()).hexdigest()
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "contradictory directory"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_incomplete_or_wrong_elf_rejected(self):
        self.elf.write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "ELF identity"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.elf.write_bytes(b"\x7fELFstate")
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 1, "to": 2}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
