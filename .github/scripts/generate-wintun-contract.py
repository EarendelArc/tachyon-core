#!/usr/bin/env python3
"""Verify the official Wintun release and emit a fail-closed sidecar contract."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


OFFICIAL_PAGE = "https://www.wintun.net/"
ARCHIVE_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
VERSION = "0.14.1"
ARCHIVE_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
DLLS = {
    "windows_amd64": (
        "wintun/bin/amd64/wintun.dll",
        "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
    ),
    "windows_arm64": (
        "wintun/bin/arm64/wintun.dll",
        "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Tachyon-Core-Release"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def verify_official() -> None:
    page = fetch(OFFICIAL_PAGE).decode("utf-8", errors="strict")
    if f"Download Wintun {VERSION}" not in page:
        raise ValueError("official Wintun page does not advertise the pinned stable version")
    if ARCHIVE_SHA256 not in page:
        raise ValueError("official Wintun page digest differs from the pinned archive digest")

    archive = fetch(ARCHIVE_URL)
    if sha256(archive) != ARCHIVE_SHA256:
        raise ValueError("official Wintun archive SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as handle:
        for architecture, (member, expected) in DLLS.items():
            try:
                data = handle.read(member)
            except KeyError as error:
                raise ValueError(f"official Wintun archive is missing {member}") from error
            if sha256(data) != expected:
                raise ValueError(f"official Wintun {architecture} DLL SHA-256 mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify-official", action="store_true")
    args = parser.parse_args()

    if args.verify_official:
        verify_official()

    document = {
        "schema_version": 1,
        "component": "wintun.dll",
        "version": VERSION,
        "source": {
            "official_page": OFFICIAL_PAGE,
            "archive_url": ARCHIVE_URL,
            "archive_sha256": ARCHIVE_SHA256,
            "verification": "official page marker, archive digest, and architecture DLL digests",
        },
        "distribution": {
            "bundled_in_tachyon_core": False,
            "managed_by": "Tachyon Prism",
            "fail_closed_if_missing_or_mismatched": True,
            "placement": "side-by-side with tachyon-core.exe",
        },
        "architectures": [
            {"platform": architecture, "path_in_official_archive": member, "sha256": digest}
            for architecture, (member, digest) in DLLS.items()
        ],
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
    except (OSError, ValueError, urllib.error.URLError, zipfile.BadZipFile) as error:
        print(f"Wintun contract generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
