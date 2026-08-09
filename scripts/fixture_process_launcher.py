#!/usr/bin/env python3
"""Launch Linux fixture children in a fresh, auditable signal session."""

from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import sys
from pathlib import Path


RESET_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def write_audit(path: Path, command: list[str]) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("launcher audit path already exists")
    payload = {
        "command": command,
        "launcher_pid": os.getpid(),
        "process_group_id": os.getpgrp(),
        "reset_signals": [item.name for item in RESET_SIGNALS],
        "session_id": os.getsid(0),
        "signal_dispositions": {
            item.name: "SIG_DFL" if signal.getsignal(item) == signal.SIG_DFL else "unexpected"
            for item in RESET_SIGNALS
        },
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("launcher temporary audit path already exists")
    descriptor = os.open(temporary, flags, 0o600)
    try:
        encoded = (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def launch(audit_file: Path, command: list[str]) -> int:
    if sys.platform != "linux":
        raise ValueError("fixture launcher requires Linux")
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise ValueError("fixture launcher requires a command after --")
    os.setsid()
    for item in RESET_SIGNALS:
        signal.signal(item, signal.SIG_DFL)
    write_audit(audit_file, command)
    os.execvpe(command[0], command, os.environ)
    return 127


def verify(audit_file: Path, expected_pid: int, expected_tokens: list[str]) -> int:
    metadata = audit_file.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("launcher audit must be a regular mode-0600 file")
    document = json.loads(audit_file.read_text(encoding="ascii"))
    expected_signals = [item.name for item in RESET_SIGNALS]
    if document.get("launcher_pid") != expected_pid:
        raise ValueError("launcher audit PID does not match the supervised child")
    if document.get("process_group_id") != expected_pid or document.get("session_id") != expected_pid:
        raise ValueError("launcher did not create a PID-owned process group and session")
    if document.get("reset_signals") != expected_signals:
        raise ValueError("launcher audit signal reset list is incomplete")
    dispositions = document.get("signal_dispositions")
    if dispositions != {name: "SIG_DFL" for name in expected_signals}:
        raise ValueError("launcher did not reset every audited signal to SIG_DFL")
    command = document.get("command")
    if not isinstance(command, list) or not command or command[0] != "env":
        raise ValueError("launcher audit command is invalid")
    for token in expected_tokens:
        if token not in command:
            raise ValueError(f"launcher audit command is missing expected token: {token}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    launch_parser = subparsers.add_parser("launch")
    launch_parser.add_argument("--audit-file", required=True, type=Path)
    launch_parser.add_argument("command", nargs=argparse.REMAINDER)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--audit-file", required=True, type=Path)
    verify_parser.add_argument("--expected-pid", required=True, type=int)
    verify_parser.add_argument("--expected-token", action="append", default=[])
    args = parser.parse_args()
    if args.action == "launch":
        return launch(args.audit_file, args.command)
    return verify(args.audit_file, args.expected_pid, args.expected_token)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"fixture process launcher failed: {error}", file=sys.stderr)
        raise SystemExit(1)
