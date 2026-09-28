import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("lapy_build", Path(__file__).resolve().parents[1] / "tools/build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class BuildTests(unittest.TestCase):
    def test_native_request_never_fetches_or_compiles(self):
        with patch.object(build, "run") as run:
            with self.assertRaisesRegex(ValueError, "backend unavailable"):
                build.build(argparse.Namespace(legacy=False))
            run.assert_not_called()

    def test_legacy_missing_sdk_does_not_fetch(self):
        with patch.object(build, "run") as run:
            with self.assertRaisesRegex(ValueError, "PS5_PAYLOAD_SDK"):
                build.build(argparse.Namespace(legacy=True, sdk=None))
            run.assert_not_called()

    def test_dependency_identity_and_modification_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.STDOUT).strip()
            git("init")
            (root / "source.cpp").write_text("original\n")
            git("add", "source.cpp")
            git("-c", "user.name=Build Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture")
            revision = git("rev-parse", "HEAD")
            build.verify_dependency(root, revision)
            with self.assertRaisesRegex(ValueError, "revision mismatch"):
                build.verify_dependency(root, "0" * 40)
            (root / "source.cpp").write_text("changed\n")
            with self.assertRaisesRegex(ValueError, "not clean"):
                build.verify_dependency(root, revision)
            (root / "source.cpp").write_text("original\n")
            (root / "injected.hpp").write_text("unexpected\n")
            with self.assertRaisesRegex(ValueError, "not clean"):
                build.verify_dependency(root, revision)

    def test_compatibility_adjustment_only_changes_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "dependency/include/kernel/proc.hpp"
            header.parent.mkdir(parents=True)
            text = "extern const uintptr_t kernel_base;\n"
            header.write_text(text)
            build.stage_headers(root / "dependency", root / "staged")
            self.assertEqual(header.read_text(), text)
            self.assertEqual((root / "staged/kernel/proc.hpp").read_text(), "extern uintptr_t kernel_base;\n")
            header.write_text("unexpected declaration\n")
            with self.assertRaisesRegex(ValueError, "match exactly"):
                build.stage_headers(root / "dependency", root / "staged")


if __name__ == "__main__":
    unittest.main()
