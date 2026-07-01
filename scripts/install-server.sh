#!/usr/bin/env bash
# Tachyon Core TGP server installer for Debian / Ubuntu.
#
# Tachyon Core is intentionally TGP-only. This script does not install or
# configure Xray. Prism/Xray is the desktop TCP proxy control plane.
#
# Usage:
#   sudo bash scripts/install-server.sh --port 443 --version latest

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

PORT=443
TACHYON_VERSION="latest"
UNINSTALL=false

INSTALL_DIR="/opt/tachyon"
CONFIG_DIR="/etc/tachyon"
LOG_DIR="/var/log/tachyon"
TACHYON_USER="tachyon"
GITHUB_REPO="${TACHYON_CORE_REPO:-EarendelArc/tachyon-core}"
GITHUB_CORE="https://api.github.com/repos/$GITHUB_REPO/releases"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)      PORT="$2";            shift 2 ;;
    --version)   TACHYON_VERSION="$2"; shift 2 ;;
    --uninstall) UNINSTALL=true;       shift ;;
    *) die "Unknown option: $1" ;;
  esac
done

check_root() {
  [[ $EUID -eq 0 ]] || die "Run as root."
}

resolve_latest() {
  curl -fsSL "$1?per_page=20" | jq -r '.[0].tag_name'
}

get_asset_url() {
  curl -fsSL "$1/tags/$2" \
    | jq -r --arg marker "$3" '.assets[] | select(.name | contains($marker)) | .browser_download_url' \
    | head -1
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
  chown -R "$TACHYON_USER:$TACHYON_USER" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
  success "System user '$TACHYON_USER' ready."
}

install_tachyon() {
  [[ "$TACHYON_VERSION" == "latest" ]] && TACHYON_VERSION=$(resolve_latest "$GITHUB_CORE")
  info "Installing tachyon-core $TACHYON_VERSION..."

  arch=$(dpkg --print-architecture)
  url=$(get_asset_url "$GITHUB_CORE" "$TACHYON_VERSION" "tachyon-core_${TACHYON_VERSION}_linux_${arch}.zip")
  [[ -n "$url" ]] || die "No tachyon-core asset for linux_${arch}"

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  curl -fL --progress-bar -o "$tmp/tachyon-core.zip" "$url"
  unzip -q "$tmp/tachyon-core.zip" -d "$tmp"
  install -m 755 "$tmp/tachyon-core" "$INSTALL_DIR/tachyon-core"

  cat > "$CONFIG_DIR/server.json" <<JSON
{
  "mode": "server",
  "server": {
    "listen": ":$PORT",
    "relay": {
      "dial_timeout": "5s",
      "idle_timeout": "60s"
    }
  },
  "tgp": {
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
