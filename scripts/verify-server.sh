#!/usr/bin/env bash
# Non-destructive Tachyon Core server diagnostics for Debian / Ubuntu.
#
# This script reads local deployment state, validates server.json, and prints
# enough context for support/debugging without revealing tgp.auth.psk.

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; WARNS=$((WARNS + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; FAILS=$((FAILS + 1)); }

MODE="auto"
CONFIG_PATH="/etc/tachyon/server.json"
BINARY_PATH="/opt/tachyon/tachyon-core"
SERVICE_NAME="tachyon-core"
DOCKER_CONFIG_PATH="/opt/tachyon-docker/config/server.json"
DOCKER_BINARY_PATH="/opt/tachyon-docker/bin/tachyon-core"
DOCKER_SERVICE_NAME="tachyon-docker"
DOCKER_CONTAINER_NAME="tachyon-core"
COMPOSE_DIR="/opt/tachyon-docker"
JOURNAL_LINES=80
LOG_LINES=80
WARNS=0
FAILS=0

usage() {
  cat <<'USAGE'
Tachyon Core server verification (read-only)

USAGE:
  sudo bash scripts/verify-server.sh [options]

OPTIONS:
  --mode auto|systemd|docker|config
                               Deployment to inspect (default: auto);
                               config only checks binary/config/relay ACL
  --config PATH                systemd config path (default: /etc/tachyon/server.json)
  --binary PATH                systemd binary path (default: /opt/tachyon/tachyon-core)
  --service NAME               systemd service name (default: tachyon-core)
  --docker-config PATH         Docker config path (default: /opt/tachyon-docker/config/server.json)
  --docker-binary PATH         Docker-mounted binary path (default: /opt/tachyon-docker/bin/tachyon-core)
  --docker-service NAME        Docker systemd service name (default: tachyon-docker)
  --container NAME             Docker container name (default: tachyon-core)
  --compose-dir PATH           Docker compose directory (default: /opt/tachyon-docker)
  --journal-lines N            journalctl lines to print (default: 80)
  --log-lines N                docker/file log lines to print (default: 80)
  --self-test                  Run local helper tests; does not inspect the host
  -h, --help                   Show this help

The script never prints tgp.auth.psk and never changes ufw, iptables,
firewalld, Docker, or systemd state.
USAGE
}

require_option_value() {
  local option="$1"
  if [[ $# -lt 2 || "${2:-}" == --* ]]; then
    echo "missing value for $option" >&2
    return 2
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)            require_option_value "$@" || return 2; MODE="$2"; shift 2 ;;
      --config)          require_option_value "$@" || return 2; CONFIG_PATH="$2"; shift 2 ;;
      --binary)          require_option_value "$@" || return 2; BINARY_PATH="$2"; shift 2 ;;
      --service)         require_option_value "$@" || return 2; SERVICE_NAME="$2"; shift 2 ;;
      --docker-config)   require_option_value "$@" || return 2; DOCKER_CONFIG_PATH="$2"; shift 2 ;;
      --docker-binary)   require_option_value "$@" || return 2; DOCKER_BINARY_PATH="$2"; shift 2 ;;
      --docker-service)  require_option_value "$@" || return 2; DOCKER_SERVICE_NAME="$2"; shift 2 ;;
      --container)       require_option_value "$@" || return 2; DOCKER_CONTAINER_NAME="$2"; shift 2 ;;
      --compose-dir)     require_option_value "$@" || return 2; COMPOSE_DIR="$2"; shift 2 ;;
      --journal-lines)   require_option_value "$@" || return 2; JOURNAL_LINES="$2"; shift 2 ;;
      --log-lines)       require_option_value "$@" || return 2; LOG_LINES="$2"; shift 2 ;;
      --self-test)       MODE="self-test"; shift ;;
      -h|--help)         usage; exit 0 ;;
      *)                 echo "unknown option: $1" >&2; usage >&2; return 2 ;;
    esac
  done
}

is_integer() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

sanitize_count() {
  local value="$1"
  local fallback="$2"
  if is_integer "$value" && (( value >= 1 && value <= 1000 )); then
    echo "$value"
  else
    echo "$fallback"
  fi
}

normalize_counts() {
  JOURNAL_LINES=$(sanitize_count "$JOURNAL_LINES" 80)
  LOG_LINES=$(sanitize_count "$LOG_LINES" 80)
}

have() {
  command -v "$1" >/dev/null 2>&1
}

section() {
  echo
  echo "== $* =="
}

json_get() {
  local path="$1"
  local filter="$2"
  have jq || return 127
  jq -er "$filter" "$path" 2>/dev/null
}

listen_port_from_value() {
  local listen="$1"
  if [[ "$listen" =~ ^:([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$listen" =~ ^\[.*\]:([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$listen" =~ :([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$listen" =~ ^[0-9]+$ ]]; then
    echo "$listen"
    return 0
  fi
  return 1
}

print_cmd() {
  echo "+ $*"
  "$@" 2>&1 || true
}

redact_psk_stream() {
  sed -E \
    -e 's/(["'\'']psk["'\''][[:space:]]*:[[:space:]]*["'\''])[^"'\'']*(["'\''])/\1<redacted>\2/Ig' \
    -e 's/((^|[^[:alnum:]_.-])psk=)[^[:space:],;]+/\1<redacted>/Ig' \
    -e 's/((^|[^[:alnum:]_.-])psk:[[:space:]]*)[^[:space:],;]+/\1<redacted>/Ig' \
    -e 's/((^|[^[:alnum:]_.-])tgp\.auth\.psk:[[:space:]]*)[^[:space:],;]+/\1<redacted>/Ig'
}

check_binary_and_validate() {
  local binary="$1"
  local config="$2"

  section "Binary and config validation"
  if [[ -x "$binary" ]]; then
    success "tachyon-core binary exists: $binary"
    echo "+ $binary version"
    if ! "$binary" version 2>&1; then
      fail "tachyon-core version command failed"
    fi
  elif [[ -f "$binary" ]]; then
    fail "binary exists but is not executable: $binary"
  else
    fail "tachyon-core binary not found: $binary"
  fi

  if [[ -r "$config" ]]; then
    success "config is readable: $config"
  elif [[ -f "$config" ]]; then
    fail "config exists but is not readable by this user: $config"
  else
    fail "config not found: $config"
  fi

  if [[ -x "$binary" && -r "$config" ]]; then
    echo "+ $binary validate --config $config"
    if "$binary" validate --config "$config" 2>&1; then
      success "config validate passed"
    else
      fail "config validate failed"
    fi
  else
    warn "skipping config validate because binary or config is unavailable"
  fi
}

check_config_security() {
  local config="$1"

  section "Config security summary"
  if [[ ! -r "$config" ]]; then
    warn "cannot inspect config security fields without read access"
    return 0
  fi
  if ! have jq; then
    warn "jq is not installed; install jq to inspect PSK and allowed_targets safely"
    return 0
  fi

  local mode
  mode=$(json_get "$config" '.mode // ""') || mode=""
  if [[ "$mode" == "server" ]]; then
    success "config mode is server"
  else
    fail "config mode is not server: ${mode:-<empty>}"
  fi

  local psk_len psk_placeholder allow_unauth
  psk_len=$(json_get "$config" '(.tgp.auth.psk // "") | length') || psk_len=0
  psk_placeholder=$(json_get "$config" '((.tgp.auth.psk // "") | ascii_downcase) == "replace-with-shared-tgp-psk"') || psk_placeholder=false
  allow_unauth=$(json_get "$config" '.tgp.auth.allow_unauthenticated == true') || allow_unauth=false
  if (( psk_len >= 16 )) && [[ "$psk_placeholder" == "false" ]]; then
    success "tgp.auth.psk is present and non-placeholder (value redacted)"
  elif [[ "$allow_unauth" == "true" ]]; then
    fail "tgp.auth.allow_unauthenticated is true; do not use this for real VPS testing"
  elif (( psk_len == 0 )); then
    fail "tgp.auth.psk is missing or empty"
  elif [[ "$psk_placeholder" == "true" ]]; then
    fail "tgp.auth.psk still uses the placeholder value"
  else
    fail "tgp.auth.psk is shorter than 16 characters"
  fi

  local target_count
  target_count=$(json_get "$config" '(.server.relay.allowed_targets // []) | length') || target_count=0
  if (( target_count > 0 )); then
    success "server.relay.allowed_targets has $target_count rule(s)"
    echo "Allowed relay targets (PSK redacted; ports required by config validation):"
    jq -r '
      (.server.relay.allowed_targets // [])
      | to_entries[]
      | "  - [" + (.key|tostring) + "] " +
        (if (.value.cidr // "") != "" then "cidr=" + .value.cidr else "domain=" + (.value.domain // "<missing>") end) +
        ", ports=" + (.value.ports // "<missing>")
    ' "$config" 2>/dev/null
  else
    fail "server.relay.allowed_targets is empty; relay is safe deny-all and will not forward game UDP"
  fi

  local listen listen_port
  listen=$(json_get "$config" '.server.listen // ""') || listen=""
  if listen_port=$(listen_port_from_value "$listen"); then
    success "server.listen is ${listen} (UDP/$listen_port)"
    VERIFY_LISTEN_PORT="$listen_port"
  else
    warn "could not parse server.listen: ${listen:-<empty>}"
    VERIFY_LISTEN_PORT=""
  fi
}

check_systemd() {
  local service="$1"

  section "systemd service"
  if ! have systemctl; then
    warn "systemctl is not available on this host"
    return 0
  fi

  if systemctl is-active --quiet "$service"; then
    success "systemd service is active: $service"
  else
    fail "systemd service is not active: $service"
  fi
  print_cmd systemctl is-active "$service"
  print_cmd systemctl is-enabled "$service"
  print_cmd systemctl status "$service" --no-pager -l
}

check_listening_port() {
  local port="$1"

  section "UDP listening port"
  if [[ -z "$port" ]]; then
    warn "skipping listen check because no UDP port was parsed from config"
    return 0
  fi
  if have ss; then
    if ss -H -lun "sport = :$port" 2>/dev/null | grep -q .; then
      success "UDP/$port appears to be listening"
    else
      fail "UDP/$port does not appear in ss listener output"
    fi
    print_cmd ss -lunp "sport = :$port"
  elif have netstat; then
    print_cmd netstat -lunp
    warn "netstat output is not filtered; look for UDP/$port manually"
  else
    warn "neither ss nor netstat is available; cannot inspect UDP listeners"
  fi
}

check_journal() {
  local service="$1"

  section "journal tail"
  if have journalctl; then
    journalctl -u "$service" -n "$JOURNAL_LINES" --no-pager 2>&1 | redact_psk_stream || true
  else
    warn "journalctl is not available"
  fi
}

check_file_log_hint() {
  local config="$1"

  if [[ ! -r "$config" ]] || ! have jq; then
    return 0
  fi
  local log_file
  log_file=$(json_get "$config" '.observability.log_file // ""') || log_file=""
  if [[ -n "$log_file" && -r "$log_file" ]]; then
    section "configured log file tail"
    tail -n "$LOG_LINES" "$log_file" 2>&1 | redact_psk_stream || true
  elif [[ -n "$log_file" ]]; then
    section "configured log file"
    warn "log file is configured but not readable: $log_file"
  fi
}

check_firewall_guidance() {
  local port="$1"

  section "Firewall and cloud security group"
  if have ufw; then
    echo "+ ufw status verbose"
    ufw status verbose 2>&1 || true
  else
    warn "ufw is not installed or not in PATH"
  fi

  if have firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
    echo "+ firewall-cmd --list-all"
    firewall-cmd --list-all 2>&1 || true
  fi

  if [[ -n "$port" ]]; then
    cat <<EOF

Manual checks:
  - Ensure the VPS firewall allows inbound UDP/$port.
  - Ensure the cloud provider security group allows inbound UDP/$port.
  - Do not open relay targets to 0.0.0.0/0 or ::/0; keep allowed_targets scoped
    to known game server CIDRs/domains and explicit UDP ports.
  - This script intentionally does not change ufw, iptables, nftables,
    firewalld, Docker, or cloud security group rules.
EOF
  else
    cat <<'EOF'

Manual checks:
  - Ensure the VPS firewall and cloud security group allow the configured TGP UDP port.
  - Do not open relay targets to 0.0.0.0/0 or ::/0; keep allowed_targets scoped
    to known game server CIDRs/domains and explicit UDP ports.
  - This script intentionally does not change ufw, iptables, nftables,
    firewalld, Docker, or cloud security group rules.
EOF
  fi
}

check_docker() {
  local container="$1"
  local compose_dir="$2"

  section "Docker deployment"
  if ! have docker; then
    fail "docker is not installed or not in PATH"
    return 0
  fi

  print_cmd docker ps -a --filter "name=^/${container}$" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
  local running
  running=$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)
  if [[ "$running" == "true" ]]; then
    success "docker container is running: $container"
  else
    fail "docker container is not running or not found: $container"
  fi
  print_cmd docker inspect -f '{{.Name}} status={{.State.Status}} running={{.State.Running}} restart={{.RestartCount}} started={{.State.StartedAt}}' "$container"

  if [[ -f "$compose_dir/docker-compose.yaml" ]]; then
    success "docker compose file exists: $compose_dir/docker-compose.yaml"
  else
    warn "docker compose file not found: $compose_dir/docker-compose.yaml"
  fi

  section "docker logs tail"
  docker logs --tail "$LOG_LINES" "$container" 2>&1 | redact_psk_stream || true
}

run_systemd_verify() {
  VERIFY_LISTEN_PORT=""
  check_binary_and_validate "$BINARY_PATH" "$CONFIG_PATH"
  check_config_security "$CONFIG_PATH"
  check_systemd "$SERVICE_NAME"
  check_listening_port "$VERIFY_LISTEN_PORT"
  check_journal "$SERVICE_NAME"
  check_file_log_hint "$CONFIG_PATH"
  check_firewall_guidance "$VERIFY_LISTEN_PORT"
}

run_docker_verify() {
  VERIFY_LISTEN_PORT=""
  check_binary_and_validate "$DOCKER_BINARY_PATH" "$DOCKER_CONFIG_PATH"
  check_config_security "$DOCKER_CONFIG_PATH"
  check_systemd "$DOCKER_SERVICE_NAME"
  check_docker "$DOCKER_CONTAINER_NAME" "$COMPOSE_DIR"
  check_listening_port "$VERIFY_LISTEN_PORT"
  check_file_log_hint "$DOCKER_CONFIG_PATH"
  check_firewall_guidance "$VERIFY_LISTEN_PORT"
}

run_config_verify() {
  VERIFY_LISTEN_PORT=""
  check_binary_and_validate "$BINARY_PATH" "$CONFIG_PATH"
  check_config_security "$CONFIG_PATH"
}

auto_detect_mode() {
  if [[ -r "$CONFIG_PATH" || -x "$BINARY_PATH" ]]; then
    echo "systemd"
    return 0
  fi
  if [[ -r "$DOCKER_CONFIG_PATH" || -x "$DOCKER_BINARY_PATH" || -d "$COMPOSE_DIR" ]]; then
    echo "docker"
    return 0
  fi
  echo "systemd"
}

make_temp_dir() {
  if have mktemp; then
    mktemp -d
    return
  fi

  local base="${TMPDIR:-/tmp}"
  local dir="$base/tachyon-verify-self-test.$$"
  mkdir -p "$dir" && echo "$dir"
}

self_test() {
  section "self-test"
  if ! have jq; then
    fail "jq is required for self-test"
    return 1
  fi

  local tmp
  tmp=$(make_temp_dir) || { fail "temporary directory creation failed"; return 1; }
  cat > "$tmp/server.json" <<'JSON'
{
  "mode": "server",
  "server": {
    "listen": ":2443",
    "relay": {
      "allowed_targets": [
        {"cidr": "198.51.100.0/24", "ports": "27015-27050"},
        {"domain": "game.example.com", "ports": "27015"}
      ]
    }
  },
  "tgp": {
    "auth": {"psk": "0123456789abcdef0123456789abcdef"}
  }
}
JSON

  local port count psk_len
  port=$(listen_port_from_value "$(json_get "$tmp/server.json" '.server.listen')")
  count=$(json_get "$tmp/server.json" '(.server.relay.allowed_targets // []) | length')
  psk_len=$(json_get "$tmp/server.json" '(.tgp.auth.psk // "") | length')
  local ok=0
  [[ "$port" == "2443" ]] || { fail "listen port helper returned $port"; ok=1; }
  [[ "$(listen_port_from_value "127.0.0.1:2444")" == "2444" ]] || { fail "host:port listen helper failed"; ok=1; }
  [[ "$(listen_port_from_value "[::1]:2445")" == "2445" ]] || { fail "IPv6 listen helper failed"; ok=1; }
  [[ "$(listen_port_from_value "2446")" == "2446" ]] || { fail "bare listen port helper failed"; ok=1; }
  [[ "$count" == "2" ]] || { fail "allowed target helper returned $count"; ok=1; }
  [[ "$psk_len" == "32" ]] || { fail "psk length helper returned $psk_len"; ok=1; }

  local original_mode="$MODE"
  local original_config="$CONFIG_PATH"
  local original_binary="$BINARY_PATH"
  MODE="auto"
  CONFIG_PATH="$tmp/server.json"
  BINARY_PATH="$tmp/tachyon-core"
  : > "$BINARY_PATH"
  chmod +x "$BINARY_PATH"
  [[ "$(auto_detect_mode)" == "systemd" ]] || { fail "auto_detect_mode did not prefer systemd"; ok=1; }
  parse_args --mode config --config "$tmp/server.json" --binary "$tmp/tachyon-core" || { fail "parse_args failed for config mode"; ok=1; }
  [[ "$MODE" == "config" ]] || { fail "parse_args did not set config mode"; ok=1; }
  MODE="$original_mode"
  CONFIG_PATH="$original_config"
  BINARY_PATH="$original_binary"

  local missing_output status
  for opt in --mode --config --binary; do
    if have timeout; then
      missing_output=$(timeout 5 bash "$0" "$opt" 2>&1 >/dev/null)
      status=$?
    else
      missing_output=$(bash "$0" "$opt" 2>&1 >/dev/null)
      status=$?
    fi
    if [[ "$status" -eq 0 ]]; then
      fail "$opt without value exited 0"
      ok=1
    elif [[ "$status" -eq 124 ]]; then
      fail "$opt without value timed out"
      ok=1
    elif [[ "$missing_output" != *"missing value for $opt"* ]]; then
      fail "$opt without value produced unclear error: ${missing_output:-<empty>}"
      ok=1
    fi
  done

  local secret="super-secret-shared-psk"
  local redacted
  redacted=$(printf '%s\n' \
    "\"psk\": \"$secret\"" \
    "'psk': '$secret'" \
    "psk=$secret" \
    "PSK: $secret" \
    "tgp.auth.psk: $secret" \
    | redact_psk_stream)
  if [[ "$redacted" == *"$secret"* ]]; then
    fail "redact_psk_stream leaked a PSK value"
    ok=1
  fi
  local redacted_count
  redacted_count=$(printf '%s' "$redacted" | grep -o "<redacted>" | wc -l | tr -d ' ')
  [[ "$redacted_count" == "5" ]] || { fail "redact_psk_stream redacted $redacted_count/5 samples"; ok=1; }

  rm -rf "$tmp"
  if (( ok == 0 )); then
    success "helper self-test passed"
  fi
  return "$ok"
}

main() {
  parse_args "$@" || exit 2
  normalize_counts

  case "$MODE" in
    self-test)
      self_test
      ;;
    auto)
      MODE=$(auto_detect_mode)
      info "auto-detected deployment mode: $MODE"
      [[ $EUID -eq 0 ]] || warn "not running as root; protected config, journal, and process details may be unreadable"
      [[ "$MODE" == "docker" ]] && run_docker_verify || run_systemd_verify
      ;;
    systemd)
      [[ $EUID -eq 0 ]] || warn "not running as root; protected config, journal, and process details may be unreadable"
      run_systemd_verify
      ;;
    docker)
      [[ $EUID -eq 0 ]] || warn "not running as root; protected config, journal, and process details may be unreadable"
      run_docker_verify
      ;;
    config)
      run_config_verify
      ;;
    *)
      echo "invalid --mode: $MODE" >&2
      usage >&2
      exit 2
      ;;
  esac

  section "Summary"
  echo "Failures: $FAILS"
  echo "Warnings: $WARNS"
  echo "PSK values were not printed. Do not paste or publish tgp.auth.psk."
  if (( FAILS > 0 )); then
    exit 1
  fi
}

main "$@"
