#!/usr/bin/env bash
# Optional TGP public E2E verifier.
#
# Default mode is local loopback smoke. Public E2E requires explicit --server,
# --target, and --psk-file/--psk, and expects a controlled UDP echo target.
# The script does not create TUN devices, modify routes, change firewalls, or
# configure systemd/Docker. It does not invoke Prism or claim to validate TUN
# capture or real game traffic.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

MODE="loopback"
SERVER="${TACHYON_E2E_SERVER:-}"
TARGET="${TACHYON_E2E_TARGET:-}"
PSK="${TACHYON_E2E_PSK:-}"
PSK_FILE=""
PAYLOAD="${TACHYON_E2E_PAYLOAD:-tachyon-e2e-probe}"
EXPECT="${TACHYON_E2E_EXPECT:-}"
EXPECT_PREFIX="${TACHYON_E2E_EXPECT_PREFIX:-}"
TIMEOUT="${TACHYON_E2E_TIMEOUT:-8s}"

usage() {
  cat <<'USAGE'
Tachyon Core TGP E2E verifier

USAGE:
  bash scripts/verify-tgp-e2e.sh [options]

SAFE DEFAULT:
  With no public target parameters, the script runs the local loopback smoke:
    bash scripts/smoke-tgp-relay.sh

PUBLIC E2E:
  Requires an already deployed Tachyon Core server and a controlled UDP echo
  target that is explicitly allowed by server.relay.allowed_targets.

  bash scripts/verify-tgp-e2e.sh \
    --mode public \
    --server vps.example.com:443 \
    --target echo.example.com:27015 \
    --psk-file ./tgp.psk

OPTIONS:
  --mode loopback|public       Verification mode (default: loopback)
  --server HOST:PORT           Tachyon Core server UDP address for public E2E
  --target HOST:PORT           Controlled UDP echo target; no default
  --psk-file PATH              File containing tgp.auth.psk; preferred
  --psk VALUE                  TGP PSK value; less safe than --psk-file
  --payload TEXT               Probe payload (default: tachyon-e2e-probe)
  --expect TEXT                Exact expected UDP response payload
  --expect-prefix TEXT         Expected UDP response prefix
  --timeout DURATION           Public E2E timeout, max 30s (default: 8s)
  --self-test                  Check script wiring without network probes
  -h, --help                   Show this help

SAFETY:
  - The script never defaults to a real game server.
  - Public E2E is opt-in and requires --server, --target, and a PSK.
  - Use a UDP echo target you control. If --expect/--expect-prefix are omitted,
    responses equal to PAYLOAD or "echo:${PAYLOAD}" are accepted.
  - This script does not create TUN devices, change routes, touch firewall
    rules, or start/stop systemd or Docker services.
  - It proves only an opt-in Core/TGP relay loop. It does not invoke Prism or
    validate TUN capture or real game behavior.
USAGE
}

require_option_value() {
  local option="$1"
  if [[ $# -lt 2 || "${2:-}" == --* ]]; then
    die "$option requires a value"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)          require_option_value "$@"; MODE="$2"; shift 2 ;;
    --server)        require_option_value "$@"; SERVER="$2"; MODE="public"; shift 2 ;;
    --target)        require_option_value "$@"; TARGET="$2"; MODE="public"; shift 2 ;;
    --psk-file)      require_option_value "$@"; PSK_FILE="$2"; MODE="public"; shift 2 ;;
    --psk)           require_option_value "$@"; PSK="$2"; MODE="public"; shift 2 ;;
    --payload)       require_option_value "$@"; PAYLOAD="$2"; shift 2 ;;
    --expect)        require_option_value "$@"; EXPECT="$2"; shift 2 ;;
    --expect-prefix) require_option_value "$@"; EXPECT_PREFIX="$2"; shift 2 ;;
    --timeout)       require_option_value "$@"; TIMEOUT="$2"; shift 2 ;;
    --self-test)     MODE="self-test"; shift ;;
    -h|--help)       usage; exit 0 ;;
    *)               echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_PACKAGE="./internal/app"
TEST_REGEX="^TestTGPRelayPublicE2EFromEnv$"

have() {
  command -v "$1" >/dev/null 2>&1
}

validate_host_port() {
  local label="$1"
  local value="$2"
  [[ -n "$value" ]] || die "$label is required"
  [[ "$value" != *":0" ]] || die "$label must not use port 0"
  if [[ "$value" =~ ^\[.*\]:([0-9]+)$ || "$value" =~ :([0-9]+)$ ]]; then
    local port="${BASH_REMATCH[1]}"
    (( port >= 1 && port <= 65535 )) || die "$label has invalid UDP port: $value"
    return 0
  fi
  die "$label must be HOST:PORT or [IPv6]:PORT: $value"
}

validate_timeout() {
  [[ "$TIMEOUT" =~ ^([0-9]+)(ms|s)$ ]] || die "--timeout must be a Go duration in ms or s, got: $TIMEOUT"
  local amount_raw="${BASH_REMATCH[1]}"
  local unit="${BASH_REMATCH[2]}"
  [[ ${#amount_raw} -le 8 ]] || die "--timeout must be >0 and <=30s, got: $TIMEOUT"
  local amount=$((10#$amount_raw))
  (( amount > 0 )) || die "--timeout must be >0 and <=30s, got: $TIMEOUT"
  if [[ "$unit" == "s" ]]; then
    (( amount <= 30 )) || die "--timeout must be >0 and <=30s, got: $TIMEOUT"
  else
    (( amount <= 30000 )) || die "--timeout must be >0 and <=30s, got: $TIMEOUT"
  fi
}

validate_expectations() {
  if [[ -n "$EXPECT" && -n "$EXPECT_PREFIX" ]]; then
    die "set only one of --expect and --expect-prefix"
  fi
}

resolve_psk() {
  if [[ -n "$PSK_FILE" && -n "${TACHYON_E2E_PSK:-}" ]]; then
    die "set either --psk-file or TACHYON_E2E_PSK, not both"
  fi
  if [[ -n "$PSK_FILE" && -n "$PSK" ]]; then
    die "set either --psk-file or --psk, not both"
  fi
  if [[ -n "$PSK_FILE" ]]; then
    [[ -r "$PSK_FILE" ]] || die "PSK file is not readable: $PSK_FILE"
    PSK="$(< "$PSK_FILE")"
    PSK="${PSK//$'\r'/}"
    PSK="${PSK//$'\n'/}"
  fi
  [[ -n "$PSK" ]] || die "public E2E requires --psk-file PATH or --psk VALUE"
  [[ ${#PSK} -ge 16 ]] || die "TGP PSK must be at least 16 characters"
}

run_go_test() {
  if have mise; then
    exec mise exec -- go test "$TEST_PACKAGE" -run "$TEST_REGEX" -count=1 -v
  fi
  exec go test "$TEST_PACKAGE" -run "$TEST_REGEX" -count=1 -v
}

run_loopback() {
  info "Running local loopback smoke only. No public UDP target will be contacted."
  exec "$BASH" "$SCRIPT_DIR/smoke-tgp-relay.sh"
}

run_public() {
  validate_host_port "--server" "$SERVER"
  validate_host_port "--target" "$TARGET"
  validate_timeout
  validate_expectations
  resolve_psk

  cd "$REPO_ROOT"
  warn "Public E2E will send one TGP probe to $SERVER and one relayed UDP probe to $TARGET."
  warn "Only use a controlled UDP echo target that is already present in server.relay.allowed_targets."
  warn "The PSK is passed to the child Go test through an environment variable and is never printed."

  export TACHYON_E2E_SERVER="$SERVER"
  export TACHYON_E2E_TARGET="$TARGET"
  export TACHYON_E2E_PSK="$PSK"
  export TACHYON_E2E_PAYLOAD="$PAYLOAD"
  export TACHYON_E2E_EXPECT="$EXPECT"
  export TACHYON_E2E_EXPECT_PREFIX="$EXPECT_PREFIX"
  export TACHYON_E2E_TIMEOUT="$TIMEOUT"
  run_go_test
}

self_test() {
  cd "$REPO_ROOT"
  [[ -f "go.mod" ]] || die "go.mod not found from $REPO_ROOT"
  [[ -f "internal/app/tgp_public_e2e_test.go" ]] || die "public E2E test file missing"
  [[ -x "$SCRIPT_DIR/smoke-tgp-relay.sh" || -f "$SCRIPT_DIR/smoke-tgp-relay.sh" ]] || die "loopback smoke script missing"
  validate_host_port "--server" "127.0.0.1:443"
  validate_host_port "--target" "[::1]:27015"
  TIMEOUT="8s"
  validate_timeout
  if (validate_host_port "--server" "127.0.0.1:0") >/dev/null 2>&1; then
    die "self-test expected port 0 to be rejected"
  fi
  if (validate_host_port "--target" "missing-port") >/dev/null 2>&1; then
    die "self-test expected a missing port to be rejected"
  fi
  TIMEOUT="0s"
  if (validate_timeout) >/dev/null 2>&1; then
    die "self-test expected a zero timeout to be rejected"
  fi
  TIMEOUT="31s"
  if (validate_timeout) >/dev/null 2>&1; then
    die "self-test expected a timeout over 30s to be rejected"
  fi
  TIMEOUT="30000ms"
  validate_timeout
  EXPECT="reply"
  EXPECT_PREFIX="rep"
  if (validate_expectations) >/dev/null 2>&1; then
    die "self-test expected conflicting response matchers to be rejected"
  fi
  EXPECT=""
  EXPECT_PREFIX=""
  validate_expectations
  local tmp_psk_file
  tmp_psk_file="${TMPDIR:-/tmp}/tachyon-e2e-psk.$$"
  printf '%s\n' "0123456789abcdef0123456789abcdef" > "$tmp_psk_file"
  PSK=""
  PSK_FILE="$tmp_psk_file"
  unset TACHYON_E2E_PSK
  resolve_psk
  rm -f "$tmp_psk_file"
  [[ ! -e "$tmp_psk_file" ]] || die "temporary PSK file was not removed"
  success "verify-tgp-e2e self-test passed"
  echo "[OK] public E2E test target: $TEST_PACKAGE -run '$TEST_REGEX'"
  echo "[OK] public validation rejects incomplete/unsafe parameters before Go or network execution"
  echo "[OK] default mode remains loopback; public mode still requires explicit server, target, and PSK"
}

case "$MODE" in
  loopback)
    run_loopback
    ;;
  public)
    run_public
    ;;
  self-test)
    self_test
    ;;
  *)
    die "invalid --mode: $MODE"
    ;;
esac
