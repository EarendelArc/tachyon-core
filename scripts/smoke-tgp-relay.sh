#!/usr/bin/env bash
# Local, non-destructive TGP relay smoke verification.
#
# This script only binds temporary 127.0.0.1 UDP ports through Go tests. It does
# not create TUN devices and does not read or change routing, firewall, systemd,
# Docker, or VPS state.

set -euo pipefail

usage() {
  cat <<'USAGE'
Tachyon Core local TGP relay smoke verification

USAGE:
  bash scripts/smoke-tgp-relay.sh [options]

OPTIONS:
  --self-test      Check script wiring without running Go tests
  -h, --help       Show this help

The smoke test covers:
  - PSK-authenticated handshake succeeds
  - missing/wrong PSK handshakes are rejected
  - UDP echo-like relay works for an allowed target
  - allowed_targets blocks denied ports and unknown targets
  - wildcard relay targets are rejected; empty ACL remains deny-all
USAGE
}

SELF_TEST=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-test) SELF_TEST=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_PACKAGE="./internal/app"
TEST_REGEX="^TestTGPRelaySmokeVerification$"

cd "$REPO_ROOT"

if [[ "$SELF_TEST" == "true" ]]; then
  [[ -f "go.mod" ]] || { echo "[FAIL] go.mod not found from $REPO_ROOT" >&2; exit 1; }
  [[ -f "internal/app/tgp_smoke_test.go" ]] || { echo "[FAIL] smoke test file missing" >&2; exit 1; }
  echo "[OK] smoke script resolves repo root: $REPO_ROOT"
  echo "[OK] smoke test target: $TEST_PACKAGE -run '$TEST_REGEX'"
  exit 0
fi

if command -v mise >/dev/null 2>&1; then
  exec mise exec -- go test "$TEST_PACKAGE" -run "$TEST_REGEX" -count=1 -v
fi

exec go test "$TEST_PACKAGE" -run "$TEST_REGEX" -count=1 -v
