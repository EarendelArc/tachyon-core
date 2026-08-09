#!/usr/bin/env python3
"""Render bilingual notes and the canonical release checksum manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path


PLATFORMS = (
    "windows_amd64",
    "windows_arm64",
    "darwin_amd64",
    "darwin_arm64",
    "linux_amd64",
    "linux_arm64",
)
AUXILIARY = (
    "BUILD_METADATA.json",
    "WINTUN_SIDECAR_CONTRACT.json",
    "EVIDENCE_MANIFEST.json",
)
VERSION_RE = re.compile(r"^v[0-9A-Za-z][0-9A-Za-z._-]*$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def render(template: Path, output: Path, version: str, commit: str) -> None:
    content = template.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    content = content.replace("{{VERSION}}", version).replace("{{COMMIT}}", commit)
    if "{{VERSION}}" in content or "{{COMMIT}}" in content:
        raise ValueError(f"release note template contains an unresolved placeholder: {template.name}")
    atomic_write(output, content.encode("utf-8"))


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def checksum_names(version: str) -> tuple[str, ...]:
    zips = tuple(f"tachyon-core_{version}_{platform}.zip" for platform in PLATFORMS)
    return (
        "RELEASE_NOTES.md",
        "RELEASE_NOTES.zh-CN.md",
        *zips,
        *AUXILIARY,
        f"tachyon-helper-evidence_{version}.tar.gz",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--release-directory", required=True, type=Path)
    parser.add_argument("--template-directory", required=True, type=Path)
    args = parser.parse_args()

    commit = args.commit.lower()
    if not VERSION_RE.fullmatch(args.version):
        raise ValueError("invalid release tag")
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be a full Git object ID")
    root = args.release_directory.resolve(strict=True)
    templates = args.template_directory.resolve(strict=True)

    render(templates / "RELEASE_NOTES.md.tmpl", root / "RELEASE_NOTES.md", args.version, commit)
    render(templates / "RELEASE_NOTES.zh-CN.md.tmpl", root / "RELEASE_NOTES.zh-CN.md", args.version, commit)

    names = checksum_names(args.version)
    missing = [name for name in names if not (root / name).is_file()]
    if missing:
        raise ValueError(f"required checksum input is missing: {missing[0]}")
    lines = [f"{digest(root / name)}  {name}\n" for name in names]
    manifest = "".join(lines).encode("ascii")
    atomic_write(root / "SHA256SUMS.txt", manifest)

    if (root / "SHA256SUMS.txt").read_bytes() != manifest:
        raise ValueError("checksum manifest verification failed")
    for line, name in zip(lines, names):
        if line[:64] != digest(root / name):
            raise ValueError(f"checksum verification failed for {name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"release metadata generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
