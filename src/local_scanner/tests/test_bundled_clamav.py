import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bundled_clamav", Path(__file__).parents[1] / "bundled_clamav.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class BundledScannerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle = self.root / "bundle"
        (self.bundle / "seed").mkdir(parents=True)
        for name in ("main.cvd", "daily.cvd", "bytecode.cvd", "main-63.cvd.sign"):
            (self.bundle / "seed" / name).write_text("seed")
        self.user = self.root / "user"
        for name, value in (("bundle_root", self.bundle), ("data_root", self.user)):
            p = patch.object(runtime, name, return_value=value)
            p.start()
            self.addCleanup(p.stop)
        runtime._status = {"ready": False, "message": "Preparing"}

    def test_first_launch_copies_definitions_and_detached_signatures(self):
        exe, database = runtime.prepare()
        self.assertEqual(exe, self.bundle / "bin" / "clamscan")
        self.assertEqual((database / "main-63.cvd.sign").read_text(), "seed")
        self.assertTrue(runtime.status()["ready"])
        self.assertEqual(runtime.process_environment()["CVD_CERTS_DIR"], str(self.bundle / "certs"))

    def test_newer_cld_is_not_replaced_by_seed_cvd(self):
        runtime.prepare()
        (self.user / "db" / "daily.cvd").unlink()
        (self.user / "db" / "daily.cld").write_text("newer")
        runtime.prepare()
        self.assertFalse((self.user / "db" / "daily.cvd").exists())
        self.assertEqual((self.user / "db" / "daily.cld").read_text(), "newer")

    def test_offline_update_keeps_scanner_ready_and_throttles_retries(self):
        with patch.object(runtime.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "offline", "")) as run:
            runtime._update()
            self.assertTrue(runtime.status()["ready"])
            self.assertIn("update unavailable", runtime.status()["message"])
            runtime._update()
            self.assertEqual(run.call_count, 1)

    def test_successful_update_uses_private_config_and_no_shell(self):
        with patch.object(runtime.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "updated", "")) as run:
            runtime._update()
            args, options = run.call_args
            self.assertIn(str(self.user / "freshclam.conf"), args[0][1])
            self.assertIn("CVDCertsDirectory", (self.user / "freshclam.conf").read_text())
            self.assertNotIn("shell", options)
            self.assertIn("definitions updated", runtime.status()["message"])

    def test_incomplete_bundle_fails_instead_of_claiming_ready(self):
        (self.bundle / "seed" / "daily.cvd").unlink()
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            runtime.prepare()
        self.assertFalse(runtime.status()["ready"])


if __name__ == "__main__":
    unittest.main()
