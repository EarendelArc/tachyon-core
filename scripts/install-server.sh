#!/usr/bin/env bash
# Tachyon Core TGP server installer for Debian / Ubuntu.
#
# Tachyon Core is intentionally TGP-only. This script does not install or
# configure Xray. Prism/Xray is the desktop TCP proxy control plane.
#
# Usage:
#   sudo bash scripts/install-server.sh --port 443 --version latest \
#     --allow-target 'cidr=198.51.100.0/24,ports=27015-27050'
#
# Or:
#   sudo TACHYON_ALLOWED_TARGETS='domain=game.example.com,ports=27015' \
#     bash scripts/install-server.sh --port 443

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

PORT="${TACHYON_PORT:-443}"
TACHYON_VERSION="latest"
UNINSTALL=false
TACHYON_PSK="${TACHYON_PSK:-}"
TACHYON_ALLOWED_TARGETS="${TACHYON_ALLOWED_TARGETS:-}"
ALLOWED_TARGET_INPUTS=()
ALLOWED_TARGET_OBJECTS=()
ALLOWED_TARGETS_JSON="[]"

INSTALL_DIR="/opt/tachyon"
CONFIG_DIR="/etc/tachyon"
LOG_DIR="/var/log/tachyon"
TACHYON_USER="tachyon"
GITHUB_REPO="${TACHYON_CORE_REPO:-EarendelArc/tachyon-core}"
GITHUB_CORE="https://api.github.com/repos/$GITHUB_REPO/releases"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      [[ $# -ge 2 ]] || die "--port requires a value"
      PORT="$2"
      shift 2
      ;;
    --version)   TACHYON_VERSION="$2"; shift 2 ;;
    --allow-target)
      ALLOWED_TARGET_INPUTS+=("$2")
      shift 2
      ;;
    --uninstall) UNINSTALL=true;       shift ;;
    *) die "Unknown option: $1" ;;
  esac
done

check_root() {
  [[ $EUID -eq 0 ]] || die "Run as root."
}

validate_listen_port() {
  local raw="$1"
  [[ "$raw" =~ ^[0-9]+$ && ${#raw} -le 5 ]] \
    || die "listen port must be a number from 1 to 65535"
  local port=$((10#$raw))
  (( port >= 1 && port <= 65535 )) \
    || die "listen port must be in range 1..65535: $raw"
}

resolve_latest() {
  curl -fsSL "$1?per_page=20" | jq -r '.[0].tag_name'
}

get_asset_url() {
  curl -fsSL "$1/tags/$2" \
    | jq -r --arg marker "$3" '.assets[] | select(.name | contains($marker)) | .browser_download_url' \
    | head -1
}

verify_archive_checksum() {
  local work_dir="$1"
  local asset_name="$2"

  grep -F "  $asset_name" "$work_dir/SHA256SUMS.txt" > "$work_dir/SHA256SUMS.asset" \
    || die "SHA256SUMS.txt does not contain $asset_name"
  (cd "$work_dir" && sha256sum -c SHA256SUMS.asset) \
    || die "Checksum verification failed for $asset_name"
}

ensure_tgp_psk() {
  if [[ -z "$TACHYON_PSK" ]]; then
    TACHYON_PSK=$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')
  fi
  [[ ${#TACHYON_PSK} -ge 16 ]] || die "TACHYON_PSK must be at least 16 characters"
  [[ "$TACHYON_PSK" =~ ^[A-Za-z0-9._~:-]+$ ]] || die "TACHYON_PSK contains characters unsafe for this installer"
}

validate_ports() {
  local raw="$1"
  [[ -n "$raw" ]] || die "allowed target ports are required; empty ports would create an unsafe all-port relay"
  [[ "$raw" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] \
    || die "allowed target ports must be a comma-separated list like 27015 or 27015-27050"

  local part start end
  IFS=',' read -ra parts <<< "$raw"
  for part in "${parts[@]}"; do
    if [[ "$part" == *-* ]]; then
      start="${part%%-*}"
      end="${part##*-}"
    else
      start="$part"
      end="$part"
    fi
    (( start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end )) \
      || die "allowed target port range out of bounds: $part"
  done
}

add_allowed_target() {
  local raw="$1"
  [[ -n "$raw" ]] || return 0
  [[ "$raw" == *,ports=* ]] \
    || die "allowed target must include explicit ports: cidr=198.51.100.0/24,ports=27015-27050"

  local target="${raw%%,ports=*}"
  local ports="${raw#*,ports=}"
  validate_ports "$ports"

  if [[ "$target" == cidr=* ]]; then
    local cidr="${target#cidr=}"
    [[ "$cidr" != "0.0.0.0/0" && "$cidr" != "::/0" ]] \
      || die "refusing wildcard relay target $cidr"
    [[ "$cidr" =~ ^[A-Za-z0-9:.\/]+$ && "$cidr" == */* ]] \
      || die "allowed target CIDR is invalid or unsafe: $cidr"
    ALLOWED_TARGET_OBJECTS+=("{\"cidr\":\"$cidr\",\"ports\":\"$ports\"}")
    return 0
  fi

  if [[ "$target" == domain=* ]]; then
    local domain="${target#domain=}"
    [[ "$domain" =~ ^[A-Za-z0-9._-]+$ && "$domain" != *":"* ]] \
      || die "allowed target domain is invalid or unsafe: $domain"
    ALLOWED_TARGET_OBJECTS+=("{\"domain\":\"$domain\",\"ports\":\"$ports\"}")
    return 0
  fi

  die "allowed target must start with cidr= or domain=: $raw"
}

render_allowed_targets_json() {
  if [[ ${#ALLOWED_TARGET_OBJECTS[@]} -eq 0 ]]; then
    echo "[]"
    return 0
  fi

  echo "["
  local i
  for i in "${!ALLOWED_TARGET_OBJECTS[@]}"; do
    local comma=","
    [[ "$i" -eq $((${#ALLOWED_TARGET_OBJECTS[@]} - 1)) ]] && comma=""
    echo "        ${ALLOWED_TARGET_OBJECTS[$i]}$comma"
  done
  echo "      ]"
}

collect_allowed_targets() {
  local item
  if [[ -n "$TACHYON_ALLOWED_TARGETS" ]]; then
    IFS=';' read -ra env_targets <<< "$TACHYON_ALLOWED_TARGETS"
    for item in "${env_targets[@]}"; do
      add_allowed_target "$item"
    done
  fi
  for item in "${ALLOWED_TARGET_INPUTS[@]}"; do
    add_allowed_target "$item"
  done

  if [[ ${#ALLOWED_TARGET_OBJECTS[@]} -eq 0 && -t 0 ]]; then
    warn "No relay allowed targets configured yet."
    warn "Enter targets one per line, e.g. cidr=198.51.100.0/24,ports=27015-27050"
    warn "Leave blank to keep the safe deny-all relay policy."
    while true; do
      read -r -p "Allowed target: " item || true
      [[ -n "$item" ]] || break
      add_allowed_target "$item"
    done
  fi

  ALLOWED_TARGETS_JSON=$(render_allowed_targets_json)
  if [[ ${#ALLOWED_TARGET_OBJECTS[@]} -eq 0 ]]; then
    warn "安全 deny-all，TGP relay 不会转发游戏 UDP，需配置后再测 / Safe deny-all: TGP relay will not forward game UDP until allowed_targets is configured."
  else
    success "Configured ${#ALLOWED_TARGET_OBJECTS[@]} relay allowed target(s)."
  fi
}

install_deps() {
  info "Installing dependencies..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl jq unzip ufw
  success "Dependencies installed."
}

create_user() {
  id "$TACHYON_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$TACHYON_USER"
  mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
  chmod 0755 "$INSTALL_DIR" "$LOG_DIR"
  chmod 0750 "$CONFIG_DIR"
  chown -R "$TACHYON_USER:$TACHYON_USER" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
  success "System user '$TACHYON_USER' ready."
}

install_tachyon() {
  [[ "$TACHYON_VERSION" == "latest" ]] && TACHYON_VERSION=$(resolve_latest "$GITHUB_CORE")
  ensure_tgp_psk
  collect_allowed_targets
  info "Installing tachyon-core $TACHYON_VERSION..."

  arch=$(dpkg --print-architecture)
  asset_name="tachyon-core_${TACHYON_VERSION}_linux_${arch}.zip"
  url=$(get_asset_url "$GITHUB_CORE" "$TACHYON_VERSION" "$asset_name")
  checksums_url=$(get_asset_url "$GITHUB_CORE" "$TACHYON_VERSION" "SHA256SUMS.txt")
  [[ -n "$url" ]] || die "No tachyon-core asset for linux_${arch}"
  [[ -n "$checksums_url" ]] || die "No SHA256SUMS.txt asset for $TACHYON_VERSION"

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  curl -fL --progress-bar -o "$tmp/$asset_name" "$url"
  curl -fsSL -o "$tmp/SHA256SUMS.txt" "$checksums_url"
  verify_archive_checksum "$tmp" "$asset_name"
  unzip -q "$tmp/$asset_name" -d "$tmp"
  install -m 755 "$tmp/tachyon-core" "$INSTALL_DIR/tachyon-core"

  install -m 0640 -o "$TACHYON_USER" -g "$TACHYON_USER" /dev/null "$CONFIG_DIR/server.json"
  cat > "$CONFIG_DIR/server.json" <<JSON
{
  "mode": "server",
  "server": {
    "listen": ":$PORT",
    "relay": {
      "dial_timeout": "5s",
      "idle_timeout": "60s",
      "max_sessions": 1024,
      "session_queue_size": 256,
      "handler_concurrency": 1024,
      "max_flows": 4096,
      "max_flows_per_session": 256,
      "allowed_targets": $ALLOWED_TARGETS_JSON
    }
  },
  "tgp": {
    "auth": {
      "psk": "$TACHYON_PSK"
    },
    "fec": {
      "data_shards": 4,
      "parity_shards": 2,
      "group_timeout": "20ms",
      "dynamic": true,
      "adapt_window": 32
    },
    "pacing": {
      "initial_rate_pps": 128,
      "max_rate_pps": 1000
    },
    "connection_migration": true,
    "multipath": false,
    "handshake_timeout": "5s",
    "session_idle_timeout": "300s"
  },
  "observability": {
    "log_level": "info",
    "log_file": "$LOG_DIR/tachyon-core.log",
    "metrics_addr": "127.0.0.1:19090"
  }
}
JSON
  chown -R "$TACHYON_USER:$TACHYON_USER" "$CONFIG_DIR"
  chmod 0640 "$CONFIG_DIR/server.json"

  cat > /etc/systemd/system/tachyon-core.service <<UNIT
[Unit]
Description=Tachyon Core TGP relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$TACHYON_USER
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=$INSTALL_DIR/tachyon-core run --config $CONFIG_DIR/server.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
StandardOutput=append:$LOG_DIR/tachyon-core.log
StandardError=append:$LOG_DIR/tachyon-core.log

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now tachyon-core
  success "tachyon-core $TACHYON_VERSION installed."
  info "TGP PSK saved in $CONFIG_DIR/server.json; copy it into the Prism Tachyon server profile."
  if [[ ${#ALLOWED_TARGET_OBJECTS[@]} -eq 0 ]]; then
    warn "Relay ACL is deny-all. Edit $CONFIG_DIR/server.json server.relay.allowed_targets before testing game UDP forwarding."
  fi
}

configure_firewall() {
  ufw allow 22/tcp comment "SSH" || true
  ufw allow "$PORT"/udp comment "Tachyon TGP" || true
  ufw --force enable
  success "Firewall configured for UDP/$PORT."
}

uninstall() {
  systemctl stop tachyon-core 2>/dev/null || true
  systemctl disable tachyon-core 2>/dev/null || true
  rm -f /etc/systemd/system/tachyon-core.service
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
  id "$TACHYON_USER" &>/dev/null && userdel "$TACHYON_USER" || true
  success "Tachyon Core server removed."
}

main() {
  validate_listen_port "$PORT"
  check_root
  if [[ "$UNINSTALL" == "true" ]]; then
    uninstall
    exit 0
  fi
  install_deps
  create_user
  install_tachyon
  configure_firewall
  success "Tachyon Core TGP relay is listening on UDP/$PORT."
}

main "$@"
