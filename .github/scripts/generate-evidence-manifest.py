#!/usr/bin/env python3
"""Validate sanitized Helper evidence and package it for a release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

from deterministic_archive import (
    ARCHIVE_GID,
    ARCHIVE_GNAME,
    ARCHIVE_UID,
    ARCHIVE_UNAME,
    FILE_MODE,
    write_tar_gz,
)


REQUIRED_FILES = (
    "health.sanitized.json",
    "ready.sanitized.json",
    "cleanup.json",
    "manifest.json",
    "manifest.sha256",
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
FORBIDDEN = re.compile(r"token|trusted_server_sha256|core_sha256", re.IGNORECASE)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(directory: Path, commit: str, run_id: str, attempt: str) -> dict[str, object]:
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("evidence commit must be a full Git object ID")
    if not run_id.isdigit() or not attempt.isdigit():
        raise ValueError("evidence run identity must be numeric")

    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(REQUIRED_FILES):
        raise ValueError(f"evidence directory contains an unexpected file set: {sorted(actual)}")

    documents = {name: load_json(directory / name) for name in REQUIRED_FILES[:4]}
    all_text = "\n".join((directory / name).read_text(encoding="utf-8") for name in REQUIRED_FILES[:4])
    if FORBIDDEN.search(all_text):
        raise ValueError("sanitized evidence contains a forbidden secret field")

    inner = documents["manifest.json"]
    if not isinstance(inner, dict):
        raise ValueError("inner evidence manifest is not an object")
    if inner.get("commit_sha", "").lower() != commit:
        raise ValueError("inner evidence manifest commit does not match the verified release commit")
    if str(inner.get("run_id")) != run_id or str(inner.get("run_attempt")) != attempt:
        raise ValueError("inner evidence manifest run identity does not match this release run")
    files = inner.get("files")
    if not isinstance(files, dict) or set(files) != set(REQUIRED_FILES[:3]):
        raise ValueError("inner evidence manifest file map is incomplete")
    for name in REQUIRED_FILES[:3]:
        digest, _ = sha256_file(directory / name)
        if files[name].lower() != digest:
            raise ValueError(f"inner evidence hash mismatch: {name}")
    manifest_digest, _ = sha256_file(directory / "manifest.json")
    recorded = (directory / "manifest.sha256").read_text(encoding="utf-8").strip().split()
    if len(recorded) != 2 or recorded[1] != "manifest.json" or recorded[0].lower() != manifest_digest:
        raise ValueError("inner evidence manifest.sha256 does not match manifest.json")

    health = documents["health.sanitized.json"]
    if not isinstance(health, dict) or health.get("status") != "not_ready" or health.get("capture_provider") != "not_ready":
        raise ValueError("Helper evidence is not the required fail-closed NotReady state")

    file_entries = []
    for name in REQUIRED_FILES:
        digest, size = sha256_file(directory / name)
        file_entries.append({"name": name, "sha256": digest, "size": size})
    return {
        "schema_version": 1,
        "source": "github-actions-helper-service-sid-harness",
        "source_commit": commit,
        "run_id": int(run_id),
        "run_attempt": int(attempt),
        "capture_state": "not_ready",
        "scope": "WFP Helper preview evidence only; no real WFP callout, kernel injection, process capture, or game E2E",
        "files": file_entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()

    evidence_dir = args.directory.resolve()
    manifest = validate(evidence_dir, args.commit.lower(), args.run_id, args.run_attempt)
    output_dir = args.output_directory.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_name = f"tachyon-helper-evidence_{args.version}.tar.gz"
    archive_path = output_dir / archive_name
    write_tar_gz(
        archive_path,
        {f"helper-evidence/{name}": (evidence_dir / name).read_bytes() for name in REQUIRED_FILES},
        args.source_date_epoch,
    )

    archive_sha256, archive_size = sha256_file(archive_path)
    manifest["release_version"] = args.version
    manifest["release_eligible"] = True
    manifest["archive"] = {
        "format": "pax-tar+gzip",
        "gid": ARCHIVE_GID,
        "gname": ARCHIVE_GNAME,
        "member_mode": f"{FILE_MODE:04o}",
        "mtime": args.source_date_epoch,
        "name": archive_name,
        "path_order": "utf8-bytewise",
        "pax_headers": {},
        "sha256": archive_sha256,
        "size": archive_size,
        "uid": ARCHIVE_UID,
        "uname": ARCHIVE_UNAME,
    }
    output_path = output_dir / "EVIDENCE_MANIFEST.json"
    output_path.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, tarfile.TarError, json.JSONDecodeError) as error:
        print(f"evidence manifest generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
