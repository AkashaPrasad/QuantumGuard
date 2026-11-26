"""Regression checks for the scanner boundary; no Docker or product required."""

import importlib.util
import contextlib
import io
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("banned_deps", ROOT / "scripts/check_banned_deps.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
zap_spec = importlib.util.spec_from_file_location("zap_report", ROOT / "scripts/check_zap_report.py")
zap = importlib.util.module_from_spec(zap_spec)
zap_spec.loader.exec_module(zap)


class DependencyBoundaryTests(unittest.TestCase):
    def names(self, filename, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / filename
            path.write_text(text, encoding="utf-8")
            return checker.packages(path)

    def test_uv_detects_transitive_banned_packages(self):
        names = self.names("uv.lock", '[[package]]\nname = "onnxruntime_gpu"\nversion = "1.0"\n')
        self.assertTrue(any(checker.BANNED.fullmatch(checker.normalize(name)) for name in names))

    def test_pnpm_scoped_and_snapshot_names_cannot_bypass_ban(self):
        for key in ("'@tensorflow/tfjs@4.0.0'", "'@huggingface/transformers@3.0.0'", "onnxruntime-node@1.0.0", "torch@1.0.0(peer@1.0)", "/@tensorflow/tfjs/4.0.0"):
            with self.subTest(key=key):
                names = self.names("pnpm-lock.yaml", "snapshots:\n  " + key + ": {}\n")
                self.assertTrue(any(checker.BANNED.fullmatch(checker.normalize(name)) for name in names))

    def test_pnpm_importer_alias_target_cannot_bypass_ban(self):
        names = self.names("pnpm-lock.yaml", "importers:\n  .:\n    dependencies:\n      helper:\n        specifier: npm:openai@1.0.0\n        version: openai@1.0.0\npackages:\n  openai@1.0.0: {}\n")
        self.assertIn("openai", names)

    def test_deterministic_statistics_and_crypto_dependencies_remain_allowed(self):
        for name in ("cryptography", "numpy", "scipy", "networkx", "fastapi", "@noble/post-quantum"):
            with self.subTest(name=name):
                self.assertIsNone(checker.BANNED.fullmatch(checker.normalize(name)))


class ImageBoundaryTests(unittest.TestCase):
    def test_all_scanner_and_base_images_have_immutable_pins(self):
        pins = {}
        for line in (ROOT / "scripts/images.lock").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                name, value = line.split("=", 1)
                if name.endswith("_IMAGE"):
                    self.assertRegex(value, r"^[\w./:-]+@sha256:[a-f0-9]{64}$")
                    pins[name] = value
        self.assertEqual(len(pins), 10)
        for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
            if line.startswith("FROM "):
                self.assertIn(line.split()[1], pins.values())

    def test_runtime_has_no_shell_entrypoint_or_healthcheck(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('ENTRYPOINT ["/app/backend/.venv/bin/python",', dockerfile)
        self.assertRegex(dockerfile, r'CMD \["/usr/local/bin/python3", "-c",')
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertNotIn("curl", dockerfile)


class ZapBoundaryTests(unittest.TestCase):
    def test_high_risk_warn_still_fails(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(zap.check({"site": [{"alerts": [{"riskcode": "3", "confidence": "2"}]}]}), 1)

    def test_empty_site_report_does_not_count_as_clean(self):
        with self.assertRaises(ValueError):
            zap.check({"site": []})

    def test_medium_risk_is_reported_for_review(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(zap.check({"site": [{"alerts": [{"riskcode": "2"}]}]}), 0)
        self.assertIn("medium findings requiring review: 1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
