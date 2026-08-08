#!/usr/bin/env python3
"""Cross-shell policy tests for Wintun generation and release validation."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
GENERATOR = SCRIPT_DIR / "generate-wintun-contract.py"
VALIDATOR = SCRIPT_DIR / "validate-release-assets.py"
STATIC_CONTRACT = REPO_ROOT / ".github" / "wintun" / "WINTUN_SIDECAR_CONTRACT.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseAssetsPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = load_module("tachyon_wintun_generator", GENERATOR)
        cls.validator = load_module("tachyon_release_validator", VALIDATOR)

    def test_offline_fixture_matches_static_contract_and_sizes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "contract.json"
            environment = os.environ.copy()
            environment["TACHYON_RELEASE_POLICY_TEST"] = "1"
            subprocess.run(
                [sys.executable, str(GENERATOR), "--offline-test-fixture", "--output", str(output)],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )
            generated = json.loads(output.read_text(encoding="utf-8"))
            tracked = json.loads(STATIC_CONTRACT.read_text(encoding="utf-8"))
            self.assertEqual(generated, tracked)
            sizes = {item["platform"]: item["size"] for item in generated["architectures"]}
            self.assertEqual(sizes, {"windows_amd64": 427552, "windows_arm64": 222488})

    def test_offline_fixture_requires_explicit_policy_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment.pop("TACHYON_RELEASE_POLICY_TEST", None)
            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    "--offline-test-fixture",
                    "--output",
                    str(Path(directory) / "contract.json"),
                ],
                check=False,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("restricted to explicit release policy tests", result.stderr)

    def test_validator_rejects_wintun_size_and_hash_mismatch(self) -> None:
        tracked = json.loads(STATIC_CONTRACT.read_text(encoding="utf-8"))
        for field, value in (("size", 1), ("sha256", "0" * 64)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                mutated = json.loads(json.dumps(tracked))
                mutated["architectures"][0][field] = value
                (root / "WINTUN_SIDECAR_CONTRACT.json").write_text(
                    json.dumps(mutated), encoding="utf-8"
                )
                with self.assertRaisesRegex(ValueError, "digest or size"):
                    self.validator.validate_wintun(root)

    def test_official_verification_failure_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not advertise"):
            self.generator.verify_official(lambda _: b"official source unavailable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
