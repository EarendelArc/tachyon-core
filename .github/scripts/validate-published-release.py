#!/usr/bin/env python3
"""Validate an immutable GitHub Release response against local release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_release(release: object, version: str, commit: str, release_dir: Path) -> int:
    if not isinstance(release, dict):
        raise ValueError("release response is not a JSON object")
    if release.get("tag_name") != version:
        raise ValueError("tag name mismatch")
    if release.get("draft") is not False:
        raise ValueError("release is still a draft")
    if release.get("prerelease") is not True:
        raise ValueError("release is not marked prerelease")
    if release.get("immutable") is not True:
        raise ValueError("release is not immutable")
    if str(release.get("target_commitish", "")).lower() != commit:
        raise ValueError("release target commit mismatch")

    expected = {path.name: path for path in release_dir.iterdir() if path.is_file()}
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise ValueError("release assets are not a JSON object list")
    names = [str(asset.get("name", "")) for asset in assets]
    if len(names) != len(set(names)):
        raise ValueError("release asset names are not unique")
    remote = {name: asset for name, asset in zip(names, assets)}
    if set(remote) != set(expected):
        raise ValueError(f"release asset set mismatch: remote={sorted(remote)} expected={sorted(expected)}")

    for name, path in expected.items():
        if remote[name].get("digest") != f"sha256:{sha256(path)}":
            raise ValueError(f"remote digest mismatch: {name}")
        if remote[name].get("size") != path.stat().st_size:
            raise ValueError(f"remote size mismatch: {name}")
    return len(expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-json", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--release-directory", required=True, type=Path)
    args = parser.parse_args()
    commit = args.commit.lower()
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be a full Git object ID")
    if not args.release_directory.is_dir():
        raise ValueError("release directory does not exist")
    release = json.loads(args.release_json.read_text(encoding="utf-8"))
    count = validate_release(release, args.version, commit, args.release_directory)
    print(f"verified immutable release {args.version} at {commit} with {count} assets")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"published release verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
