#!/usr/bin/env python3
"""Fail-closed validation for alpha.24 release metadata and sidecar assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path


PLATFORMS = (
    ("windows", "amd64", ".exe"),
    ("windows", "arm64", ".exe"),
    ("darwin", "amd64", ""),
    ("darwin", "arm64", ""),
    ("linux", "amd64", ""),
    ("linux", "arm64", ""),
)
WIN_TUN = {
    "version": "0.14.1",
    "archive_sha256": "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51",
    "windows_amd64": {
        "sha256": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
        "size": 427552,
    },
    "windows_arm64": {
        "sha256": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
        "size": 222488,
    },
}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def digest(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON document is not an object: {path.name}")
    return value


def validate_build_metadata(root: Path, version: str, commit: str) -> None:
    document = read_json(root / "BUILD_METADATA.json")
    release = document.get("release")
    artifacts = document.get("artifacts")
    if document.get("schema_version") != 1 or not isinstance(release, dict) or not isinstance(artifacts, list):
        raise ValueError("BUILD_METADATA.json has an invalid schema")
    if release.get("version") != version or str(release.get("commit", "")).lower() != commit:
        raise ValueError("BUILD_METADATA.json release identity does not match the verified commit")
    if not str(release.get("go_version", "")).strip() or not isinstance(release.get("source_date_epoch"), int):
        raise ValueError("BUILD_METADATA.json is missing deterministic build fields")
    if len(artifacts) != len(PLATFORMS):
        raise ValueError("BUILD_METADATA.json must contain exactly six platform entries")

    for item, (asset_os, asset_arch, extension) in zip(artifacts, PLATFORMS):
        if not isinstance(item, dict) or item.get("os") != asset_os or item.get("arch") != asset_arch:
            raise ValueError("BUILD_METADATA.json platform ordering is invalid")
        zip_name = f"tachyon-core_{version}_{asset_os}_{asset_arch}.zip"
        if item.get("zip") != zip_name:
            raise ValueError(f"BUILD_METADATA.json has an invalid ZIP name: {zip_name}")
        archive = root / zip_name
        zip_hash, zip_size = digest(archive)
        if item.get("zip_sha256") != zip_hash or item.get("zip_size") != zip_size:
            raise ValueError(f"BUILD_METADATA.json ZIP digest mismatch: {zip_name}")
        binaries = item.get("binaries")
        if not isinstance(binaries, list) or len(binaries) != 2:
            raise ValueError(f"BUILD_METADATA.json binary list is invalid: {zip_name}")
        expected = {f"tachyon-core{extension}", f"tachyonctl{extension}"}
        with zipfile.ZipFile(archive) as handle:
            names = set(handle.namelist())
            for binary in binaries:
                if not isinstance(binary, dict) or binary.get("name") not in expected:
                    raise ValueError(f"BUILD_METADATA.json contains an invalid binary: {zip_name}")
                data = handle.read(str(binary["name"]))
                if binary.get("sha256") != hashlib.sha256(data).hexdigest() or binary.get("size") != len(data):
                    raise ValueError(f"BUILD_METADATA.json binary digest mismatch: {zip_name}:{binary['name']}")
            if expected - names:
                raise ValueError(f"ZIP is missing a required binary: {zip_name}")


def validate_wintun(root: Path) -> None:
    document = read_json(root / "WINTUN_SIDECAR_CONTRACT.json")
    source = document.get("source")
    distribution = document.get("distribution")
    architectures = document.get("architectures")
    if document.get("schema_version") != 1 or document.get("component") != "wintun.dll":
        raise ValueError("WINTUN_SIDECAR_CONTRACT.json has an invalid schema")
    if document.get("version") != WIN_TUN["version"] or not isinstance(source, dict) or not isinstance(distribution, dict):
        raise ValueError("Wintun contract version/source is not pinned to the official stable release")
    if source.get("archive_sha256") != WIN_TUN["archive_sha256"]:
        raise ValueError("Wintun contract archive digest does not match the official stable release")
    if distribution.get("bundled_in_tachyon_core") is not False or distribution.get("fail_closed_if_missing_or_mismatched") is not True:
        raise ValueError("Wintun contract is not an external fail-closed Prism dependency")
    if not isinstance(architectures, list) or len(architectures) != 2:
        raise ValueError("Wintun contract must cover Windows AMD64 and ARM64")
    for item in architectures:
        expected = WIN_TUN.get(str(item.get("platform"))) if isinstance(item, dict) else None
        if not isinstance(item, dict) or not isinstance(expected, dict):
            raise ValueError("Wintun contract contains an unverified architecture")
        if item.get("sha256") != expected["sha256"] or item.get("size") != expected["size"]:
            raise ValueError("Wintun contract contains an unverified architecture digest or size")


def validate_evidence(root: Path, version: str, commit: str) -> None:
    document = read_json(root / "EVIDENCE_MANIFEST.json")
    archive = document.get("archive")
    if document.get("schema_version") != 1 or document.get("release_version") != version:
        raise ValueError("EVIDENCE_MANIFEST.json release identity is invalid")
    if str(document.get("source_commit", "")).lower() != commit:
        raise ValueError("EVIDENCE_MANIFEST.json commit does not match the verified release commit")
    if document.get("source") != "github-actions-helper-service-sid-harness" or document.get("release_eligible") is not True:
        raise ValueError("release evidence is not from the exact successful Helper Service SID harness")
    if document.get("capture_state") != "not_ready" or not isinstance(archive, dict):
        raise ValueError("release evidence must remain fail-closed NotReady preview evidence")
    archive_name = str(archive.get("name", ""))
    expected_name = f"tachyon-helper-evidence_{version}.tar.gz"
    if archive_name != expected_name:
        raise ValueError("EVIDENCE_MANIFEST.json archive name is invalid")
    archive_path = root / archive_name
    archive_hash, archive_size = digest(archive_path)
    if archive.get("sha256") != archive_hash or archive.get("size") != archive_size:
        raise ValueError("EVIDENCE_MANIFEST.json archive digest mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-directory", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    commit = args.commit.lower()
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be a full Git object ID")
    validate_build_metadata(args.release_directory, args.version, commit)
    validate_wintun(args.release_directory)
    validate_evidence(args.release_directory, args.version, commit)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(f"release asset validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
