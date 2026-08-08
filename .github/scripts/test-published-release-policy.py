#!/usr/bin/env python3
"""Persistent positive and negative fixtures for published release validation."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "validate-published-release.py"
VERSION = "v9.8.7-alpha.6"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def load_validator():
    spec = importlib.util.spec_from_file_location("tachyon_published_release_validator", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublishedReleasePolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.release_dir = Path(self.temporary.name)
        (self.release_dir / "asset.bin").write_bytes(b"tachyon fixture\n")
        (self.release_dir / "SHA256SUMS.txt").write_bytes(b"fixture manifest\n")
        assets = []
        for path in sorted(self.release_dir.iterdir()):
            assets.append(
                {
                    "name": path.name,
                    "digest": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
                    "size": path.stat().st_size,
                }
            )
        self.release = {
            "tag_name": VERSION,
            "draft": False,
            "prerelease": True,
            "immutable": True,
            "target_commitish": COMMIT,
            "assets": assets,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, release: dict[str, object], message: str) -> None:
        with self.assertRaisesRegex(ValueError, message):
            self.validator.validate_release(release, VERSION, COMMIT, self.release_dir)

    def test_positive_fixture_passes(self) -> None:
        self.assertEqual(
            self.validator.validate_release(self.release, VERSION, COMMIT, self.release_dir),
            2,
        )

    def test_is_immutable_false_fails(self) -> None:
        release = copy.deepcopy(self.release)
        release.pop("immutable")
        release["isImmutable"] = False
        self.assert_rejected(release, "release is not immutable")

    def test_target_commit_mismatch_fails(self) -> None:
        release = copy.deepcopy(self.release)
        release["target_commitish"] = "f" * 40
        self.assert_rejected(release, "release target commit mismatch")

    def test_digest_mismatch_fails(self) -> None:
        release = copy.deepcopy(self.release)
        release["assets"][0]["digest"] = "sha256:" + "0" * 64
        self.assert_rejected(release, "remote digest mismatch")

    def test_size_mismatch_fails(self) -> None:
        release = copy.deepcopy(self.release)
        release["assets"][0]["size"] += 1
        self.assert_rejected(release, "remote size mismatch")

    def test_missing_asset_fails(self) -> None:
        release = copy.deepcopy(self.release)
        release["assets"].pop()
        self.assert_rejected(release, "release asset set mismatch")

    def test_extra_asset_fails(self) -> None:
        release = copy.deepcopy(self.release)
        release["assets"].append(
            {"name": "unexpected.bin", "digest": "sha256:" + "0" * 64, "size": 0}
        )
        self.assert_rejected(release, "release asset set mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=2)
