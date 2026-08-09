#!/usr/bin/env python3
"""Create deterministic, non-production fixtures for release policy tests."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from deterministic_archive import write_zip as write_deterministic_zip


PLATFORMS = (
    ("windows", "amd64", ".exe"),
    ("windows", "arm64", ".exe"),
    ("darwin", "amd64", ""),
    ("darwin", "arm64", ""),
    ("linux", "amd64", ""),
    ("linux", "arm64", ""),
)


def write_zip(path: Path, platform: str, architecture: str, extension: str, source_date_epoch: int) -> None:
    core_name = f"tachyon-core{extension}"
    ctl_name = f"tachyonctl{extension}"
    entries = {
        core_name: f"fixture core {platform}/{architecture}\n".encode(),
        ctl_name: f"fixture ctl {platform}/{architecture}\n".encode(),
        "README.md": b"fixture\n",
        "README.zh-CN.md": b"fixture\n",
    }
    write_deterministic_zip(
        path,
        entries,
        source_date_epoch,
        executable_names=(core_name, ctl_name),
    )


def write_evidence(directory: Path, commit: str, run_id: str, attempt: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    documents = {
        "health.sanitized.json": {"status": "not_ready", "capture_provider": "not_ready"},
        "ready.sanitized.json": {"status": "not_ready"},
        "cleanup.json": {"status": "ok"},
    }
    for name, document in documents.items():
        (directory / name).write_text(
            json.dumps(document, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    hashes = {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in documents
    }
    inner = {
        "commit_sha": commit,
        "files": hashes,
        "run_attempt": int(attempt),
        "run_id": int(run_id),
    }
    (directory / "manifest.json").write_text(
        json.dumps(inner, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest_hash = hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest()
    (directory / "manifest.sha256").write_text(
        f"{manifest_hash}  manifest.json\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", default="1")
    parser.add_argument("--run-attempt", default="1")
    parser.add_argument("--source-date-epoch", default=0, type=int)
    args = parser.parse_args()
    args.release_dir.mkdir(parents=True, exist_ok=True)
    for platform, architecture, extension in PLATFORMS:
        name = f"tachyon-core_{args.version}_{platform}_{architecture}.zip"
        write_zip(args.release_dir / name, platform, architecture, extension, args.source_date_epoch)
    write_evidence(args.evidence_dir, args.commit.lower(), args.run_id, args.run_attempt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
