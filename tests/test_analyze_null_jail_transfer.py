import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_null_jail_transfer_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_null_jail_transfer.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class NullJailTransferAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log, self.server = root / "transfer.log", root / "server.json"
        self.build, self.elf = root / "build.json", root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "e" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "null-jail-two-donor-pointer-transfer",
            "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.held = 64
        self.returned = 63
        self.write_run()

    def write_run(self):
        ident = self.build_id
        messages = [
            f"probe_start build={ident} firmware=12020000 mode=null-jail-two-donors",
            f"target_ready build={ident} private=1 root_system=1 jail_null=1 ref_hint=1",
            f"transfer_sample build={ident} phase=baseline hold=60 use=59",
            f"donor_ready build={ident} role=source private=1 root_system=1 jail_null=1 ref_hint=1",
            f"donor_ready build={ident} role=receiver private=1 root_system=1 jail_null=1 ref_hint=1",
            f"transfer_sample build={ident} phase=both_held hold={self.held} use={self.held - 1}",
            f"transfer_sample build={ident} phase=donated hold=64 use=63",
            f"transfer_sample build={ident} phase=source_released hold=63 use=62",
            f"transfer_sample build={ident} phase=returned hold={self.returned} use={self.returned - 1}",
            f"transfer_sample build={ident} phase=baseline_restored hold=60 use=59",
            f"probe_result build={ident} stage=complete error=0 source_reaped=1 receiver_reaped=1 parent_jail_owned=0",
        ]
        raw = ("HELLO ps5log/1 title=LAPYSWAP app=probe boot=0x1\n" +
               "".join(f"{i}\t{i}\tMARK\t{msg}\n" for i, msg in
                       enumerate(messages, 1)) +
               "BYE seq=11 reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYSWAP", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 11, "last_seq": 11}))

    def test_balanced_transfer(self):
        self.assertTrue(analysis.analyze(self.log, self.server, self.build,
                                         self.elf)["balanced"])

    def test_wrong_donor_count_or_return_rejected(self):
        self.held = 63
        self.write_run()
        with self.assertRaisesRegex(ValueError, "not balanced"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.held = 64
        self.returned = 64
        self.write_run()
        with self.assertRaisesRegex(ValueError, "not balanced"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_stream_and_artifact_identity_enforced(self):
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 2, "to": 3}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.write_run()
        self.elf.write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "ELF identity"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
