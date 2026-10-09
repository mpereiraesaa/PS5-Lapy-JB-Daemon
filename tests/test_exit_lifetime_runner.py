import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "exit_lifetime_runner", ROOT / "tools/run_exit_lifetime_probe.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class ExitLifetimeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {"build_id": "test-build", "elf_sha256": "a" * 64}
        self.stream = (
            b"MARK stopped_kill_guard build=test-build "
            b"external_kill_queued=1 fd_retained=1\n"
            b"MARK target_exit_lifetime build=test-build retained_proc=1 "
            b"private_fd_before=1 fd_cleared=1 ucred_cleared=1 polls=2\n"
            b"MARK exit_lifetime_result build=test-build "
            b"external_kill_queued=1 stopped_fd_retained=1 killed=1 "
            b"retained_proc=1 fd_cleared=1 ucred_cleared=1 reaped=1\n"
            b"MARK probe_result build=test-build stage=complete error=0\n"
            b"BYE test-build\n")

    def test_complete_lifetime_proof_passes(self):
        result = RUNNER.evaluate_stream(self.manifest, self.stream, "", [])
        self.assertTrue(result["proof"])
        self.assertFalse(result["kernel_panic"])

    def test_missing_reap_or_panic_fails(self):
        missing = RUNNER.evaluate_stream(
            self.manifest, self.stream.replace(b"reaped=1", b"reaped=0"), "", [])
        panic = RUNNER.evaluate_stream(
            self.manifest, self.stream, "panic: synthetic test", [])
        self.assertFalse(missing["proof"])
        self.assertTrue(panic["kernel_panic"])


if __name__ == "__main__":
    unittest.main()
