#!/usr/bin/env python3
"""Exercise release generators twice and enforce the cross-platform golden bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


VERSION = "v9.8.7-alpha.6"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
SOURCE_DATE_EPOCH = 0
GOLDEN_FILES = (
    "RELEASE_NOTES.md",
    "RELEASE_NOTES.zh-CN.md",
    "EVIDENCE_MANIFEST.json",
    f"tachyon-helper-evidence_{VERSION}.tar.gz",
    "SHA256SUMS.txt",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(repo: Path, script: str, *arguments: object, timezone_name: str = "UTC") -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["TZ"] = timezone_name
    subprocess.run(
        [sys.executable, str(repo / ".github" / "scripts" / script), *(str(value) for value in arguments)],
        cwd=repo,
        env=environment,
        check=True,
    )


def perturb_evidence(directory: Path, reverse: bool) -> None:
    names = sorted((path.name for path in directory.iterdir()), reverse=reverse)
    payloads = {name: (directory / name).read_bytes() for name in names}
    for name in names:
        (directory / name).unlink()
    for index, name in enumerate(names):
        path = directory / name
        path.write_bytes(payloads[name])
        os.chmod(path, 0o600 if reverse else 0o644)
        os.utime(path, (1_700_000_000 + index, 1_600_000_000 + index))


def generate(repo: Path, root: Path, reverse: bool) -> Path:
    release = root / "release"
    evidence = root / "evidence"
    invoke(
        repo,
        "create-release-policy-fixtures.py",
        "--release-dir", release,
        "--evidence-dir", evidence,
        "--version", VERSION,
        "--commit", COMMIT,
        "--run-id", "1",
        "--run-attempt", "1",
        "--source-date-epoch", str(SOURCE_DATE_EPOCH),
        timezone_name="Pacific/Kiritimati" if reverse else "America/Los_Angeles",
    )
    perturb_evidence(evidence, reverse)
    invoke(
        repo,
        "generate-build-metadata.py",
        "--version", VERSION,
        "--commit", COMMIT,
        "--source-date-epoch", str(SOURCE_DATE_EPOCH),
        "--build-time", "1970-01-01T00:00:00Z",
        "--go-version", "go1.test",
        "--release-directory", release,
        "--output", release / "BUILD_METADATA.json",
    )
    shutil.copyfile(repo / ".github" / "wintun" / "WINTUN_SIDECAR_CONTRACT.json", release / "WINTUN_SIDECAR_CONTRACT.json")
    invoke(
        repo,
        "generate-evidence-manifest.py",
        "--directory", evidence,
        "--version", VERSION,
        "--commit", COMMIT,
        "--run-id", "1",
        "--run-attempt", "1",
        "--source-date-epoch", str(SOURCE_DATE_EPOCH),
        "--output-directory", release,
    )
    invoke(
        repo,
        "validate-release-assets.py",
        "--release-directory", release,
        "--version", VERSION,
        "--commit", COMMIT,
    )
    invoke(
        repo,
        "prepare-release-metadata.py",
        "--version", VERSION,
        "--commit", COMMIT,
        "--release-directory", release,
        "--template-directory", repo / ".github" / "release-notes",
    )
    return release


def verify_tar(release: Path) -> None:
    archive_path = release / f"tachyon-helper-evidence_{VERSION}.tar.gz"
    raw = archive_path.read_bytes()
    if raw[:3] != b"\x1f\x8b\x08" or raw[3] != 0 or raw[4:8] != b"\0\0\0\0" or raw[9] != 255:
        raise AssertionError("gzip header must fix flags, mtime, filename omission, and OS=unknown")
    document = json.loads((release / "EVIDENCE_MANIFEST.json").read_text(encoding="utf-8"))
    contract = document["archive"]
    expected_contract = {
        "format": "pax-tar+gzip",
        "gid": 0,
        "gname": "root",
        "member_mode": "0644",
        "mtime": SOURCE_DATE_EPOCH,
        "path_order": "utf8-bytewise",
        "pax_headers": {},
        "uid": 0,
        "uname": "root",
    }
    for key, value in expected_contract.items():
        if contract.get(key) != value:
            raise AssertionError(f"evidence manifest archive contract differs for {key}")
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if names != sorted(names, key=lambda name: name.encode("utf-8")):
            raise AssertionError("tar members are not UTF-8 bytewise sorted")
        for member in members:
            if not member.isfile() or (member.uid, member.gid) != (0, 0):
                raise AssertionError(f"tar owner/type differs: {member.name}")
            if (member.uname, member.gname, member.mode, member.mtime) != ("root", "root", 0o644, 0):
                raise AssertionError(f"tar identity/mode/time differs: {member.name}")
            if member.pax_headers:
                raise AssertionError(f"tar member contains undeclared PAX headers: {member.name}")


def verify_zips(release: Path) -> None:
    for archive_path in sorted(release.glob("tachyon-core_*.zip")):
        extension = ".exe" if "_windows_" in archive_path.name else ""
        executable = {f"tachyon-core{extension}", f"tachyonctl{extension}"}
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if names != sorted(names, key=lambda name: name.encode("utf-8")):
                raise AssertionError(f"ZIP paths are not bytewise sorted: {archive_path.name}")
            if archive.comment:
                raise AssertionError(f"ZIP contains a host comment: {archive_path.name}")
            for info in infos:
                expected_mode = 0o755 if info.filename in executable else 0o644
                actual_mode = (info.external_attr >> 16) & 0o777
                if info.date_time != (1980, 1, 1, 0, 0, 0) or actual_mode != expected_mode:
                    raise AssertionError(f"ZIP metadata differs: {archive_path.name}:{info.filename}")
                if info.compress_type != zipfile.ZIP_STORED or info.extra or info.comment or info.create_system != 3:
                    raise AssertionError(f"ZIP contains platform/compressor metadata: {archive_path.name}:{info.filename}")


def compare_release(first: Path, second: Path) -> None:
    first_names = sorted(path.name for path in first.iterdir() if path.is_file())
    second_names = sorted(path.name for path in second.iterdir() if path.is_file())
    if first_names != second_names or len(first_names) != 13:
        raise AssertionError("repeat release file sets differ or do not contain exactly 13 assets")
    for name in first_names:
        if (first / name).read_bytes() != (second / name).read_bytes():
            raise AssertionError(f"repeat generation differs byte-for-byte: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update-golden", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    golden = repo / ".github" / "testdata" / "release-metadata" / "golden"
    with tempfile.TemporaryDirectory(prefix="tachyon-reproducible-release-") as temporary:
        root = Path(temporary)
        first = generate(repo, root / "first", reverse=False)
        second = generate(repo, root / "second", reverse=True)
        compare_release(first, second)
        verify_tar(first)
        verify_zips(first)

        if args.update_golden:
            golden.mkdir(parents=True, exist_ok=True)
            for name in GOLDEN_FILES:
                shutil.copyfile(first / name, golden / name)
        for name in GOLDEN_FILES:
            expected = golden / name
            if not expected.is_file() or (first / name).read_bytes() != expected.read_bytes():
                raise AssertionError(f"production output differs from cross-platform golden: {name}")
            print(f"{sha256(first / name)}  {name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"reproducible release fixture failed: {error}", file=sys.stderr)
        raise SystemExit(1)
