import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "lapy_root_native_analysis",
    Path(__file__).resolve().parents[1] / "tools/analyze_root_native_refs.py")
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class NativeRootReferenceAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log = root / "native.log"
        self.server = root / "server.json"
        self.build = root / "build.json"
        self.elf = root / "probe.elf"
        self.elf.write_bytes(b"\x7fELFsample")
        self.build_id = "b" * 64
        self.build.write_text(json.dumps({
            "schema": "lapy-probe-build/1", "build_id": self.build_id,
            "mode": "root-vnode-native-open-close", "console_validated": False,
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest()}))
        self.messages = [
            f"probe_start build={self.build_id} firmware=12020000 mode=native-open-close count=4",
            f"directory_identity build={self.build_id} root_null=0 root_system=1 jail_null=1 jail_system=0",
        ]
        for index in range(9):
            phase = "baseline" if index == 0 else "held" if index <= 4 else "released"
            step = 0 if index == 0 else index if index <= 4 else index - 4
            delta = index if index <= 4 else 8 - index
            self.messages.append(
                f"native_sample build={self.build_id} phase={phase} step={step} "
                f"hold_offset=0x1bc hold={60 + delta} "
                f"use_offset=0x1c0 use={59 + delta}")
        self.messages.append(
            f"probe_result build={self.build_id} stage=complete error=0 cleanup_error=0")
        self.write_run()

    def write_run(self):
        records = "".join(f"{i}\t{i}\tMARK\t{msg}\n"
                          for i, msg in enumerate(self.messages, 1))
        raw = ("HELLO ps5log/1 title=LAPYOWN app=probe boot=0x1\n" +
               records + "BYE seq=12 reason=probe-complete\n").encode()
        self.log.write_bytes(raw)
        self.server.write_text(json.dumps({
            "protocol": "ps5log/1", "title": "LAPYOWN", "clean": True,
            "bye": True, "gaps": [], "raw_lines": 0, "oversized_lines": 0,
            "log_path": self.log.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "records": 12, "last_seq": 12}))

    def test_balanced_native_lifecycle_and_broken_step(self):
        result = analysis.analyze(self.log, self.server, self.build, self.elf)
        self.assertTrue(result["balanced"])
        self.assertEqual((result["baseline_hold"], result["baseline_use"]),
                         (60, 59))
        self.messages[5] = self.messages[5].replace("hold=63", "hold=62")
        self.write_run()
        with self.assertRaisesRegex(ValueError, "unbalanced"):
            analysis.analyze(self.log, self.server, self.build, self.elf)

    def test_incomplete_stream_and_wrong_elf_rejected(self):
        server = json.loads(self.server.read_text())
        server["gaps"] = [{"from": 4, "to": 5}]
        self.server.write_text(json.dumps(server))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            analysis.analyze(self.log, self.server, self.build, self.elf)
        self.write_run()
        self.elf.write_bytes(b"different ELF")
        with self.assertRaisesRegex(ValueError, "identity"):
            analysis.analyze(self.log, self.server, self.build, self.elf)


if __name__ == "__main__":
    unittest.main()
