#!/usr/bin/env python3
"""Generate deterministic build metadata from the six release archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath


PLATFORMS = (
    ("windows", "amd64", ".exe"),
    ("windows", "arm64", ".exe"),
    ("darwin", "amd64", ""),
    ("darwin", "arm64", ""),
    ("linux", "amd64", ""),
    ("linux", "arm64", ""),
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def read_binary(archive: Path, name: str) -> tuple[str, int]:
    with zipfile.ZipFile(archive) as handle:
        names = handle.namelist()
        if len(names) != len(set(names)):
            raise ValueError(f"archive contains duplicate names: {archive.name}")
        for member in names:
            path = PurePosixPath(member)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"archive contains unsafe path: {archive.name}:{member}")
        if name not in names:
            raise ValueError(f"archive is missing {name}: {archive.name}")
        info = handle.getinfo(name)
        if info.is_dir():
            raise ValueError(f"archive entry is a directory: {archive.name}:{name}")
        data = handle.read(name)
        return sha256_bytes(data), len(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--build-time", required=True)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--release-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    commit = args.commit.lower()
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be a full Git object ID")
    if not args.version.startswith("v"):
        raise ValueError("version must start with v")
    if not args.go_version.strip():
        raise ValueError("go version is required")

    artifacts = []
    for asset_os, asset_arch, extension in PLATFORMS:
        asset_name = f"tachyon-core_{args.version}_{asset_os}_{asset_arch}.zip"
        archive = args.release_directory / asset_name
        if not archive.is_file():
            raise ValueError(f"missing release archive: {asset_name}")
        zip_sha256, zip_size = sha256_file(archive)
        core_name = f"tachyon-core{extension}"
        ctl_name = f"tachyonctl{extension}"
        core_sha256, core_size = read_binary(archive, core_name)
        ctl_sha256, ctl_size = read_binary(archive, ctl_name)
        artifacts.append(
            {
                "os": asset_os,
                "arch": asset_arch,
                "zip": asset_name,
                "zip_sha256": zip_sha256,
                "zip_size": zip_size,
                "binaries": [
                    {"name": core_name, "sha256": core_sha256, "size": core_size},
                    {"name": ctl_name, "sha256": ctl_sha256, "size": ctl_size},
                ],
            }
        )

    document = {
        "schema_version": 1,
        "release": {
            "version": args.version,
            "commit": commit,
            "source_date_epoch": args.source_date_epoch,
            "build_time": args.build_time,
            "go_version": args.go_version,
        },
        "artifacts": artifacts,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"build metadata generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
