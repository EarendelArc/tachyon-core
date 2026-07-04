#!/usr/bin/env bash
# Read-only Tachyon Core server support bundle collector.
#
# The collector writes a timestamped local report/bundle for support review. It
# only reads system state and log tails; it never changes systemd, Docker,
# firewall, packet filter, route, or proxy state.

set -uo pipefail

MODE="auto"
CONFIG_PATH="/etc/tachyon/server.json"
BINARY_PATH="/opt/tachyon/tachyon-core"
SERVICE_NAME="tachyon-core"
DOCKER_CONFIG_PATH="/opt/tachyon-docker/config/server.json"
DOCKER_BINARY_PATH="/opt/tachyon-docker/bin/tachyon-core"
DOCKER_SERVICE_NAME="tachyon-docker"
DOCKER_CONTAINER_NAME="tachyon-core"
COMPOSE_DIR="/opt/tachyon-docker"
JOURNAL_LINES=120
LOG_LINES=120
OUTPUT_DIR="."
FORMAT="tar.gz"
SELF_TEST=false

usage() {
  cat <<'USAGE'
Tachyon Core server diagnostics support bundle (read-only)

USAGE:
  sudo bash scripts/collect-server-diagnostics.sh [options]

OPTIONS:
  --mode auto|systemd|docker|config
                               Deployment to inspect (default: auto)
  --config PATH                systemd config path (default: /etc/tachyon/server.json)
  --binary PATH                systemd binary path (default: /opt/tachyon/tachyon-core)
  --service NAME               systemd service name (default: tachyon-core)
  --docker-config PATH         Docker config path (default: /opt/tachyon-docker/config/server.json)
  --docker-binary PATH         Docker-mounted binary path (default: /opt/tachyon-docker/bin/tachyon-core)
  --docker-service NAME        Docker systemd service name (default: tachyon-docker)
  --container NAME             Docker container name (default: tachyon-core)
  --compose-dir PATH           Docker compose directory (default: /opt/tachyon-docker)
  --journal-lines N            journalctl lines to collect (default: 120, max: 1000)
  --log-lines N                docker/file log lines to collect (default: 120, max: 1000)
  --output-dir PATH            Directory for the timestamped output (default: current dir)
  --format tar.gz|txt          Output format (default: tar.gz)
  --self-test                  Run helper tests; does not inspect the host
  -h, --help                   Show this help

The collector is read-only. It redacts common secret forms including PSK,
token, uuid, private_key, password, and subscription/proxy URLs, but you must
manually inspect the generated file before sending it back or posting publicly.
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
      --output-dir)      require_option_value "$@" || return 2; OUTPUT_DIR="$2"; shift 2 ;;
      --format)          require_option_value "$@" || return 2; FORMAT="$2"; shift 2 ;;
      --self-test)       SELF_TEST=true; shift ;;
      -h|--help)         usage; exit 0 ;;
      *)                 echo "unknown option: $1" >&2; usage >&2; return 2 ;;
    esac
  done
}

have() {
  command -v "$1" >/dev/null 2>&1
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

normalize_options() {
  JOURNAL_LINES=$(sanitize_count "$JOURNAL_LINES" 120)
  LOG_LINES=$(sanitize_count "$LOG_LINES" 120)
  case "$MODE" in
    auto|systemd|docker|config) ;;
    *) echo "invalid --mode: $MODE" >&2; return 2 ;;
  esac
  case "$FORMAT" in
    tar.gz|txt) ;;
    *) echo "invalid --format: $FORMAT" >&2; return 2 ;;
  esac
}

make_temp_dir() {
  if have mktemp; then
    mktemp -d
    return
  fi

  local base="${TMPDIR:-/tmp}"
  local dir="$base/tachyon-diagnostics.$$"
  mkdir -p "$dir" && echo "$dir"
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

redact_secret_stream() {
  sed -E \
    -e 's/(["'\'']?(psk|token|access_token|refresh_token|api_key|secret|uuid|private_key|private-key|password|passwd|subscription_url|subscription-url|subscription)["'\'']?[[:space:]]*[:=][[:space:]]*["'\'']?)[^"'\''[:space:],;}]+/\1<redacted>/Ig' \
    -e 's/((^|[^[:alnum:]_.-])tgp\.auth\.psk[[:space:]]*[:=][[:space:]]*)[^[:space:],;]+/\1<redacted>/Ig' \
    -e 's#https?://[^[:space:]<>"'\'']*(token|subscription|subscribe|sub|password|passwd|private_key|psk|secret|key)[^[:space:]<>"'\'']*#<redacted-url>#Ig' \
    -e 's#(vmess|vless|trojan|ss|ssr|hysteria2|hy2|tuic)://[^[:space:]<>"'\'']+#<redacted-url>#Ig' \
    -e 's#(subscription|sub)://[^[:space:]<>"'\'']+#<redacted-url>#Ig' \
    -e 's/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}/<redacted-uuid>/g'
}

write_header() {
  local title="$1"
  {
    echo
    echo "== $title =="
  } >> "$REPORT_FILE"
}

append_cmd() {
  local title="$1"
  shift
  write_header "$title"
  {
    echo "+ $*"
    "$@" 2>&1 | redact_secret_stream || true
  } >> "$REPORT_FILE"
}

append_text() {
  local title="$1"
  shift
  write_header "$title"
  printf '%s\n' "$@" | redact_secret_stream >> "$REPORT_FILE"
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

config_for_mode() {
  case "$1" in
    docker) echo "$DOCKER_CONFIG_PATH" ;;
    *) echo "$CONFIG_PATH" ;;
  esac
}

binary_for_mode() {
  case "$1" in
    docker) echo "$DOCKER_BINARY_PATH" ;;
    *) echo "$BINARY_PATH" ;;
  esac
}

append_os_summary() {
  write_header "OS and kernel"
  {
    if [[ -r /etc/os-release ]]; then
      echo "+ /etc/os-release"
      sed -n '1,40p' /etc/os-release 2>&1 | redact_secret_stream || true
    else
      echo "/etc/os-release is not readable"
    fi
    echo
    echo "+ uname -a"
    uname -a 2>&1 | redact_secret_stream || true
    echo
    echo "+ date -u"
    date -u '+%Y-%m-%dT%H:%M:%SZ' 2>&1 || true
  } >> "$REPORT_FILE"
}

append_binary_and_config_summary() {
  local mode="$1"
  local binary
  local config
  binary=$(binary_for_mode "$mode")
  config=$(config_for_mode "$mode")

  write_header "Tachyon Core version and config validation"
  {
    echo "mode=$mode"
    echo "binary=$binary"
    echo "config=$config"
    if [[ -x "$binary" ]]; then
      echo
      echo "+ $binary version"
      "$binary" version 2>&1 | redact_secret_stream || true
    else
      echo "binary is not executable or not found"
    fi
    if [[ -x "$binary" && -r "$config" ]]; then
      echo
      echo "+ $binary validate --config $config"
      "$binary" validate --config "$config" 2>&1 | redact_secret_stream || true
    elif [[ ! -r "$config" ]]; then
      echo "config is not readable or not found"
    else
      echo "skipping validation because binary is unavailable"
    fi
  } >> "$REPORT_FILE"
}

append_allowed_targets_summary() {
  local mode="$1"
  local config
  config=$(config_for_mode "$mode")

  write_header "Config and allowed_targets summary"
  {
    if [[ ! -r "$config" ]]; then
      echo "config is not readable: $config"
      return 0
    fi
    if ! have jq; then
      echo "jq is unavailable; cannot summarize JSON config fields safely"
      return 0
    fi

    local config_mode listen port target_count psk_len placeholder allow_unauth
    config_mode=$(json_get "$config" '.mode // ""') || config_mode=""
    listen=$(json_get "$config" '.server.listen // ""') || listen=""
    target_count=$(json_get "$config" '(.server.relay.allowed_targets // []) | length') || target_count=0
    psk_len=$(json_get "$config" '(.tgp.auth.psk // "") | length') || psk_len=0
    placeholder=$(json_get "$config" '((.tgp.auth.psk // "") | ascii_downcase) == "replace-with-shared-tgp-psk"') || placeholder=false
    allow_unauth=$(json_get "$config" '.tgp.auth.allow_unauthenticated == true') || allow_unauth=false

    echo "config_mode=${config_mode:-<empty>}"
    echo "server.listen=${listen:-<empty>}"
    if port=$(listen_port_from_value "$listen"); then
      echo "parsed_udp_port=$port"
      LISTEN_PORT="$port"
    else
      echo "parsed_udp_port=<unparsed>"
      LISTEN_PORT=""
    fi
    echo "tgp.auth.psk_present=$([[ "$psk_len" -gt 0 ]] && echo yes || echo no)"
    echo "tgp.auth.psk_length=$psk_len"
    echo "tgp.auth.psk_placeholder=$placeholder"
    echo "tgp.auth.allow_unauthenticated=$allow_unauth"
    echo "allowed_targets_count=$target_count"
    if [[ "$target_count" -gt 0 ]]; then
      jq -r '
        (.server.relay.allowed_targets // [])
        | to_entries[]
        | "  - [" + (.key|tostring) + "] " +
          (if (.value.cidr // "") != "" then "cidr=" + .value.cidr else "domain=" + (.value.domain // "<missing>") end) +
          ", ports=" + (.value.ports // "<missing>")
      ' "$config" 2>/dev/null | redact_secret_stream || true
    fi
  } >> "$REPORT_FILE"
}

append_systemd_status() {
  local service="$1"
  if ! have systemctl; then
    append_text "systemd service status" "systemctl is unavailable"
    return 0
  fi
  append_cmd "systemd service is-active" systemctl is-active "$service"
  append_cmd "systemd service is-enabled" systemctl is-enabled "$service"
  append_cmd "systemd service status" systemctl status "$service" --no-pager -l
}

append_docker_status() {
  local container="$1"
  if ! have docker; then
    append_text "Docker container status" "docker is unavailable"
    return 0
  fi
  append_cmd "Docker container list" docker ps -a --filter "name=^/${container}$" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
  append_cmd "Docker container inspect summary" docker inspect -f '{{.Name}} status={{.State.Status}} running={{.State.Running}} restart={{.RestartCount}} started={{.State.StartedAt}}' "$container"
}

append_udp_listener() {
  local port="$1"
  if [[ -z "$port" ]]; then
    append_text "UDP listening port" "No UDP port was parsed from config."
    return 0
  fi
  if have ss; then
    append_cmd "UDP listening port" ss -lunp "sport = :$port"
  elif have netstat; then
    append_cmd "UDP listeners" netstat -lunp
  else
    append_text "UDP listening port" "Neither ss nor netstat is available."
  fi
}

append_log_tails() {
  local mode="$1"
  if [[ "$mode" == "docker" ]]; then
    if have journalctl; then
      append_cmd "Docker systemd journal tail" journalctl -u "$DOCKER_SERVICE_NAME" -n "$JOURNAL_LINES" --no-pager
    fi
    if have docker; then
      append_cmd "Docker logs tail" docker logs --tail "$LOG_LINES" "$DOCKER_CONTAINER_NAME"
    fi
  else
    if have journalctl; then
      append_cmd "systemd journal tail" journalctl -u "$SERVICE_NAME" -n "$JOURNAL_LINES" --no-pager
    else
      append_text "systemd journal tail" "journalctl is unavailable"
    fi
  fi

  local config log_file
  config=$(config_for_mode "$mode")
  if [[ -r "$config" ]] && have jq; then
    log_file=$(json_get "$config" '.observability.log_file // ""') || log_file=""
    if [[ -n "$log_file" && -r "$log_file" ]]; then
      append_cmd "Configured log file tail" tail -n "$LOG_LINES" "$log_file"
    elif [[ -n "$log_file" ]]; then
      append_text "Configured log file" "configured log file is not readable: $log_file"
    fi
  fi
}

append_verify_server_output() {
  local mode="$1"
  local verify_script="$SCRIPT_DIR/verify-server.sh"
  local output_file="$WORK_DIR/verify-server-output.txt"
  local summary_file="$WORK_DIR/verify-server-summary.txt"

  if [[ ! -f "$verify_script" ]]; then
    append_text "verify-server output summary" "verify-server.sh was not found next to this script"
    return 0
  fi

  {
    bash "$verify_script" \
      --mode "$mode" \
      --config "$CONFIG_PATH" \
      --binary "$BINARY_PATH" \
      --service "$SERVICE_NAME" \
      --docker-config "$DOCKER_CONFIG_PATH" \
      --docker-binary "$DOCKER_BINARY_PATH" \
      --docker-service "$DOCKER_SERVICE_NAME" \
      --container "$DOCKER_CONTAINER_NAME" \
      --compose-dir "$COMPOSE_DIR" \
      --journal-lines "$JOURNAL_LINES" \
      --log-lines "$LOG_LINES" 2>&1 || true
  } | redact_secret_stream > "$output_file"

  {
    echo "verify_server_output_file=verify-server-output.txt"
    grep -E '^\[FAIL\]|^\[WARN\]|^Failures:|^Warnings:' "$output_file" 2>/dev/null || true
  } > "$summary_file"

  write_header "verify-server output summary"
  cat "$summary_file" >> "$REPORT_FILE"
}

write_readme_first() {
  cat > "$WORK_DIR/README-FIRST.txt" <<'README'
Tachyon Core server diagnostics support bundle

This bundle was generated by scripts/collect-server-diagnostics.sh. The
collector is intended to be read-only and redacts common secret forms, including
PSK, token, uuid, private_key, password, and subscription/proxy URLs.

Before sending this file back or posting it publicly, manually inspect every
included text file. Do not send tgp.auth.psk, full private subscription URLs,
tokens, private keys, passwords, SSH keys, or unrelated provider/account
secrets.
README
}

readonly_command_inventory() {
  cat <<'COMMANDS'
cat /etc/os-release
uname -a
date -u
tachyon-core version
tachyon-core validate --config
systemctl is-active
systemctl is-enabled
systemctl status --no-pager -l
journalctl -u -n --no-pager
docker ps -a --filter --format
docker inspect -f
docker logs --tail
ss -lunp
netstat -lunp
tail -n
bash scripts/verify-server.sh
tar -czf
COMMANDS
}

self_test() {
  local ok=0
  local secret="super-secret-value"
  local uuid="123e4567-e89b-12d3-a456-426614174000"
  local redacted

  redacted=$(printf '%s\n' \
    "\"psk\": \"$secret\"" \
    "token=$secret" \
    "uuid=$uuid" \
    "private_key: $secret" \
    "password=$secret" \
    "subscription_url=https://example.com/subscription?token=$secret" \
    "vmess://abcdef0123456789" \
    "plain uuid $uuid" \
    | redact_secret_stream)

  if [[ "$redacted" == *"$secret"* || "$redacted" == *"$uuid"* || "$redacted" == *"vmess://abcdef0123456789"* ]]; then
    echo "[FAIL] redaction self-test leaked a sample secret" >&2
    ok=1
  fi

  [[ "$(listen_port_from_value ":2443")" == "2443" ]] || { echo "[FAIL] :port parsing failed" >&2; ok=1; }
  [[ "$(listen_port_from_value "127.0.0.1:2444")" == "2444" ]] || { echo "[FAIL] host:port parsing failed" >&2; ok=1; }
  [[ "$(listen_port_from_value "[::1]:2445")" == "2445" ]] || { echo "[FAIL] IPv6 port parsing failed" >&2; ok=1; }

  local inventory
  inventory=$(readonly_command_inventory)
  if printf '%s\n' "$inventory" | grep -Eiq '(systemctl[[:space:]].*(start|stop|restart|reload|enable|disable)([[:space:]]|$)|docker[[:space:]].*(run|rm|stop|restart)([[:space:]]|$)|ufw[[:space:]].*(allow|deny|delete|enable|disable)([[:space:]]|$)|iptables|ip6tables|nft[[:space:]].*(add|delete|flush)([[:space:]]|$)|firewall-cmd[[:space:]].*(add|remove|reload)([[:space:]]|$))'; then
    echo "[FAIL] read-only command inventory contains a mutating command" >&2
    ok=1
  fi

  parse_args --format txt --mode config --output-dir /tmp >/dev/null || { echo "[FAIL] parse_args failed" >&2; ok=1; }
  normalize_options || { echo "[FAIL] normalize_options failed" >&2; ok=1; }

  if (( ok == 0 )); then
    echo "[OK] diagnostics collector self-test passed"
  fi
  return "$ok"
}

collect() {
  local resolved_mode="$MODE"
  if [[ "$resolved_mode" == "auto" ]]; then
    resolved_mode=$(auto_detect_mode)
  fi

  WORK_DIR=$(make_temp_dir) || { echo "failed to create temporary directory" >&2; return 1; }
  REPORT_FILE="$WORK_DIR/report.txt"
  SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
  LISTEN_PORT=""

  local timestamp
  timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
  mkdir -p "$OUTPUT_DIR" || { echo "failed to create output directory: $OUTPUT_DIR" >&2; return 1; }

  write_readme_first
  {
    echo "Tachyon Core server diagnostics report"
    echo "generated_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "collector_mode=$resolved_mode"
    echo "read_only=true"
    echo "manual_review_required=true"
    echo
    echo "Do not send this report until you have manually checked it for secrets."
  } > "$REPORT_FILE"

  append_os_summary
  append_binary_and_config_summary "$resolved_mode"
  append_allowed_targets_summary "$resolved_mode"
  if [[ "$resolved_mode" == "docker" ]]; then
    append_systemd_status "$DOCKER_SERVICE_NAME"
    append_docker_status "$DOCKER_CONTAINER_NAME"
  elif [[ "$resolved_mode" == "systemd" ]]; then
    append_systemd_status "$SERVICE_NAME"
  fi
  append_udp_listener "$LISTEN_PORT"
  append_log_tails "$resolved_mode"
  append_verify_server_output "$resolved_mode"

  local output_path
  if [[ "$FORMAT" == "txt" ]]; then
    output_path="$OUTPUT_DIR/tachyon-server-diagnostics-$timestamp.txt"
    {
      cat "$WORK_DIR/README-FIRST.txt"
      echo
      cat "$REPORT_FILE"
      if [[ -f "$WORK_DIR/verify-server-output.txt" ]]; then
        echo
        echo "== Full verify-server output =="
        cat "$WORK_DIR/verify-server-output.txt"
      fi
    } > "$output_path"
  else
    if ! have tar; then
      echo "tar is required for --format tar.gz; rerun with --format txt" >&2
      return 1
    fi
    output_path="$OUTPUT_DIR/tachyon-server-diagnostics-$timestamp.tar.gz"
    tar -C "$WORK_DIR" -czf "$output_path" . || return 1
  fi

  rm -rf "$WORK_DIR"
  echo "Created read-only Tachyon diagnostics: $output_path"
  echo "Manual review required before sending. Do not include PSK, full subscription URLs, tokens, private keys, or passwords."
}

main() {
  parse_args "$@" || exit 2
  if [[ "$SELF_TEST" == "true" ]]; then
    self_test
    exit $?
  fi
  normalize_options || exit 2
  collect
}

main "$@"
