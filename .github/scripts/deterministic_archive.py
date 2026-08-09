#!/usr/bin/env python3
"""Cross-platform deterministic ZIP and tar.gz archive primitives."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import stat
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping


ARCHIVE_UID = 0
ARCHIVE_GID = 0
ARCHIVE_UNAME = "root"
ARCHIVE_GNAME = "root"
FILE_MODE = 0o644
EXECUTABLE_MODE = 0o755
ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z, the earliest ZIP timestamp.


def _sort_key(name: str) -> bytes:
    return name.encode("utf-8")


def _validate_archive_name(name: str) -> None:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive path: {name!r}")
    if str(path) != name or any(part in ("", ".") for part in path.parts):
        raise ValueError(f"non-canonical archive path: {name!r}")


def _atomic_output(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    return descriptor, Path(temporary)


def write_tar_gz(
    output: Path,
    entries: Mapping[str, bytes],
    source_date_epoch: int,
    *,
    mode: int = FILE_MODE,
) -> None:
    """Write a PAX tar inside a deterministic gzip envelope."""
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    if not entries:
        raise ValueError("archive must contain at least one file")

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT, pax_headers={}) as archive:
        for name in sorted(entries, key=_sort_key):
            _validate_archive_name(name)
            payload = entries[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mtime = source_date_epoch
            info.mode = mode
            info.uid = ARCHIVE_UID
            info.gid = ARCHIVE_GID
            info.uname = ARCHIVE_UNAME
            info.gname = ARCHIVE_GNAME
            info.pax_headers = {}
            archive.addfile(info, io.BytesIO(payload))

    descriptor, temporary = _atomic_output(output)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            # Level 0 avoids compressor-version choices; evidence is intentionally tiny.
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=0, mtime=source_date_epoch) as stream:
                stream.write(tar_buffer.getvalue())
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _zip_timestamp(source_date_epoch: int) -> tuple[int, int, int, int, int, int]:
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    normalized = max(source_date_epoch, ZIP_EPOCH)
    normalized -= normalized % 2
    value = datetime.fromtimestamp(normalized, tz=timezone.utc)
    if value.year > 2107:
        raise ValueError("source date epoch exceeds the ZIP timestamp range")
    return value.year, value.month, value.day, value.hour, value.minute, value.second


def collect_regular_files(source_directory: Path) -> dict[str, bytes]:
    root = source_directory.resolve(strict=True)
    entries: dict[str, bytes] = {}
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        _validate_archive_name(relative)
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"archive input must not be a symbolic link: {relative}")
        if candidate.is_dir():
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"archive input must be a regular file: {relative}")
        entries[relative] = candidate.read_bytes()
    if not entries:
        raise ValueError("archive input directory contains no regular files")
    return entries


def write_zip(
    output: Path,
    entries: Mapping[str, bytes],
    source_date_epoch: int,
    *,
    executable_names: Iterable[str] = (),
) -> None:
    """Write a host-independent, stored ZIP with normalized POSIX metadata."""
    if not entries:
        raise ValueError("archive must contain at least one file")
    executable = set(executable_names)
    unknown = executable - set(entries)
    if unknown:
        raise ValueError(f"executable entries are missing from input: {sorted(unknown)}")
    timestamp = _zip_timestamp(source_date_epoch)

    descriptor, temporary = _atomic_output(output)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, mode="w", compression=zipfile.ZIP_STORED, strict_timestamps=True) as archive:
            archive.comment = b""
            for name in sorted(entries, key=_sort_key):
                _validate_archive_name(name)
                info = zipfile.ZipInfo(filename=name, date_time=timestamp)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 10
                info.flag_bits = 0
                info.internal_attr = 0
                info.external_attr = (stat.S_IFREG | (EXECUTABLE_MODE if name in executable else FILE_MODE)) << 16
                info.extra = b""
                info.comment = b""
                archive.writestr(info, entries[name])
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("zip",), required=True)
    parser.add_argument("--source-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--executable", action="append", default=[])
    args = parser.parse_args()
    entries = collect_regular_files(args.source_directory)
    write_zip(args.output.resolve(), entries, args.source_date_epoch, executable_names=args.executable)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"deterministic archive generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
