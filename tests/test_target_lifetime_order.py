"""Keep every target kernel-pointer read behind the ptrace stop."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TargetLifetimeOrderTests(unittest.TestCase):
    def test_run_one_attaches_before_target_snapshot(self):
        source = (ROOT / "source/owned_root_daemon.c").read_text()
        run_one = source[source.index("static int run_one("):
                         source.index("#if LAPY_ELF_HELPER", source.index("static int run_one("))]
        attach = run_one.index("ptrace(PT_ATTACH")
        wait = run_one.index("await_target_stop(")
        credentials = run_one.index("save_credentials(pid")
        self.assertLess(attach, wait)
        self.assertLess(wait, credentials)
        self.assertNotIn("snapshot_with_delay(pid", run_one[:attach])
        self.assertIn("struct snapshot before = {0}", run_one)

    def test_stop_is_observed_before_delayed_snapshot(self):
        source = (ROOT / "source/owned_root_daemon.c").read_text()
        await_stop = source[source.index("static int await_target_stop("):
                            source.index("/* A traced title", source.index("static int await_target_stop("))]
        observed = await_stop.index("*stop_observed = 1")
        snapshot = await_stop.index("snapshot_with_delay(pid")
        self.assertLess(observed, snapshot)


if __name__ == "__main__":
    unittest.main()
