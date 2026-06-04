#!/usr/bin/env bash
# =============================================================================
# Tachyon Core — Server Mode Bare-Metal Installer (Debian / Ubuntu)
# =============================================================================
# Installs tachyon-core (server mode) + xray-core as systemd services.
# Both services use the same tachyon-core binary; xray is managed separately.
#
# Usage:
#   sudo bash install.sh --domain vpn.example.com --email admin@example.com
#
# Options:
#   --domain   <FQDN>        TLS domain (required)
#   --email    <EMAIL>       Let's Encrypt email (required)
#   --uuid     <UUID>        VLESS UUID (auto-generated if omitted)
#   --port     <PORT>        Listen port (default: 443)
#   --version  <TAG>         tachyon-core release tag (default: latest)
#   --xray-version <TAG>     xray-core release tag (default: latest)
#   --uninstall              Remove all components
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
DOMAIN=""; EMAIL=""; UUID_VAL=""; PORT=443
TACHYON_VERSION="latest"; XRAY_VERSION="latest"; UNINSTALL=false
XRAY_INTERNAL_PORT=18443

INSTALL_DIR="/opt/tachyon"; XRAY_DIR="/opt/xray"
CONFIG_DIR="/etc/tachyon"; CERT_DIR="/etc/tachyon/certs"; LOG_DIR="/var/log/tachyon"
TACHYON_USER="tachyon"
GITHUB_CORE="https://api.github.com/repos/tachyon-space/tachyon-core/releases"
GITHUB_XRAY="https://api.github.com/repos/XTLS/Xray-core/releases"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)        DOMAIN="$2";          shift 2 ;;
    --email)         EMAIL="$2";           shift 2 ;;
    --uuid)          UUID_VAL="$2";        shift 2 ;;
    --port)          PORT="$2";            shift 2 ;;
    --version)       TACHYON_VERSION="$2"; shift 2 ;;
    --xray-version)  XRAY_VERSION="$2";   shift 2 ;;
    --uninstall)     UNINSTALL=true;       shift   ;;
    *) die "Unknown option: $1" ;;
  esac
done

check_root() { [[ $EUID -eq 0 ]] || die "Run as root."; }
check_args() {
  [[ "$UNINSTALL" == "true" ]] && return
  [[ -n "$DOMAIN" ]] || die "--domain required"
  [[ -n "$EMAIL"  ]] || die "--email required"
}

resolve_latest() {
  curl -fsSL "$1/latest" | grep '"tag_name"' | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

get_asset_url() {
  curl -fsSL "$1/tags/$2" | grep '"browser_download_url"' | grep -i "$3" \
    | head -1 | sed 's/.*": *"\([^"]*\)".*/\1/'
}

# ── Step 1: Dependencies ──────────────────────────────────────────────────────
install_deps() {
  info "Installing dependencies..."
  apt-get update -qq
  apt-get install -y -qq curl wget unzip tar ca-certificates socat openssl jq ufw
  success "Dependencies installed."
}

# ── Step 2: System user ───────────────────────────────────────────────────────
create_user() {
  id "$TACHYON_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$TACHYON_USER"
  mkdir -p "$INSTALL_DIR" "$XRAY_DIR" "$CONFIG_DIR" "$CERT_DIR" "$LOG_DIR"
  chown -R "$TACHYON_USER:$TACHYON_USER" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
  success "System user '$TACHYON_USER' ready."
}

# ── Step 3: TLS certificate ───────────────────────────────────────────────────
install_certs() {
  [[ -f "$HOME/.acme.sh/acme.sh" ]] || curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
  ufw allow 80/tcp 2>/dev/null || true
  "$HOME/.acme.sh/acme.sh" --issue -d "$DOMAIN" --standalone --keylength ec-256 \
    --log "$LOG_DIR/acme.log" || warn "Certificate may already exist."
  "$HOME/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" --ecc \
    --cert-file "$CERT_DIR/cert.pem" --key-file "$CERT_DIR/key.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd "systemctl reload tachyon-core xray 2>/dev/null || true"
  chown -R "$TACHYON_USER:$TACHYON_USER" "$CERT_DIR"
  chmod 600 "$CERT_DIR/key.pem"
  ufw delete allow 80/tcp 2>/dev/null || true
  success "TLS certificate installed."
}

# ── Step 4: Install xray-core ─────────────────────────────────────────────────
install_xray() {
  [[ "$XRAY_VERSION" == "latest" ]] && XRAY_VERSION=$(resolve_latest "$GITHUB_XRAY")
  info "Installing xray-core $XRAY_VERSION..."
  ARCH=$(dpkg --print-architecture)
  case "$ARCH" in amd64) XA="linux-64" ;; arm64) XA="linux-arm64-v8a" ;; *) die "Unsupported arch: $ARCH" ;; esac
  URL=$(get_asset_url "$GITHUB_XRAY" "$XRAY_VERSION" "Xray-${XA}.zip")
  [[ -n "$URL" ]] || die "No xray asset for $XA"
  TMP=$(mktemp -d)
  wget -q --show-progress -O "$TMP/xray.zip" "$URL"
  unzip -q -o "$TMP/xray.zip" -d "$TMP/xray"
  install -m 755 "$TMP/xray/xray" "$XRAY_DIR/xray"
  rm -rf "$TMP"
  [[ -n "$UUID_VAL" ]] || UUID_VAL=$(cat /proc/sys/kernel/random/uuid)
  # Generate xray server config
  cat > "$CONFIG_DIR/xray-server.json" <<JSON
{
  "log": { "loglevel": "warning", "access": "$LOG_DIR/xray-access.log", "error": "$LOG_DIR/xray-error.log" },
  "inbounds": [{
    "listen": "127.0.0.1", "port": $XRAY_INTERNAL_PORT, "protocol": "vless",
    "settings": { "clients": [{ "id": "$UUID_VAL", "flow": "xtls-rprx-vision" }], "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": {
        "dest": "www.apple.com:443", "serverNames": ["$DOMAIN"],
        "privateKey": "__GENERATE_WITH_XRAY_X25519__",
        "shortIds": ["$(openssl rand -hex 4)"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
JSON
  cat > /etc/systemd/system/xray.service <<UNIT
[Unit]
Description=Xray Core (Tachyon managed)
After=network-online.target
[Service]
Type=simple
User=$TACHYON_USER
ExecStart=$XRAY_DIR/xray run -config $CONFIG_DIR/xray-server.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
StandardOutput=append:$LOG_DIR/xray.log
StandardError=append:$LOG_DIR/xray.log
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload && systemctl enable --now xray
  success "xray-core $XRAY_VERSION installed. UUID: $UUID_VAL"
}

# ── Step 5: Install tachyon-core (server mode) ────────────────────────────────
install_tachyon() {
  [[ "$TACHYON_VERSION" == "latest" ]] && TACHYON_VERSION=$(resolve_latest "$GITHUB_CORE")
  info "Installing tachyon-core $TACHYON_VERSION..."
  ARCH=$(dpkg --print-architecture)
  URL=$(get_asset_url "$GITHUB_CORE" "$TACHYON_VERSION" "tachyon-core_linux_${ARCH}.tar.gz")
  [[ -n "$URL" ]] || die "No tachyon-core asset for $ARCH"
  TMP=$(mktemp -d)
  wget -q --show-progress -O "$TMP/tachyon-core.tar.gz" "$URL"
  tar -xzf "$TMP/tachyon-core.tar.gz" -C "$TMP"
  install -m 755 "$TMP/tachyon-core" "$INSTALL_DIR/tachyon-core"
  rm -rf "$TMP"
  # Generate server config
  cat > "$CONFIG_DIR/server.json" <<JSON
{
  "mode": "server",
  "server": {
    "listen": ":$PORT",
    "tls": {
      "cert": "$CERT_DIR/fullchain.pem",
      "key": "$CERT_DIR/key.pem"
    },
    "xray_backend": {
      "addr": "127.0.0.1:$XRAY_INTERNAL_PORT"
    },
    "relay": {
      "dial_timeout": "5s",
      "idle_timeout": "60s"
    }
  },
  "tgp": {
    "fec": {
      "data_shards": 4,
      "parity_shards": 2,
      "group_timeout": "20ms"
    },
    "pacing": {
      "initial_rate_pps": 128,
      "max_rate_pps": 1000
    },
    "connection_migration": true,
    "multipath": true
  },
  "xray": {
    "install_dir": "$XRAY_DIR/",
    "config_file": "$CONFIG_DIR/xray-server.json"
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
Description=Tachyon Core (server mode)
After=network-online.target xray.service
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
  systemctl daemon-reload && systemctl enable --now tachyon-core
  success "tachyon-core $TACHYON_VERSION installed."
}

# ── Step 6: Firewall ──────────────────────────────────────────────────────────
configure_fw() {
  ufw allow 22/tcp comment "SSH"
  ufw allow "$PORT"/tcp comment "Tachyon TLS"
  ufw allow "$PORT"/udp comment "Tachyon TGP"
  ufw --force enable
  success "Firewall configured."
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
  systemctl stop tachyon-core xray 2>/dev/null || true
  systemctl disable tachyon-core xray 2>/dev/null || true
  rm -f /etc/systemd/system/tachyon-core.service /etc/systemd/system/xray.service
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR" "$XRAY_DIR" "$CONFIG_DIR" "$LOG_DIR"
  id "$TACHYON_USER" &>/dev/null && userdel "$TACHYON_USER"
  success "Uninstalled."
}

main() {
  check_root; check_args
  [[ "$UNINSTALL" == "true" ]] && { uninstall; exit 0; }
  echo -e "\n${CYAN}╔══════════════════════════════════════════╗"
  echo -e "║  Tachyon Core Server Installer v1.0      ║"
  echo -e "╚══════════════════════════════════════════╝${NC}\n"
  install_deps; create_user; install_certs; install_xray; install_tachyon; configure_fw
  echo -e "\n${GREEN}══ Installation Complete ══════════════════════════════${NC}"
  echo -e "  UUID   : ${CYAN}$UUID_VAL${NC}"
  echo -e "  Domain : ${CYAN}$DOMAIN${NC}"
  echo -e "\n${YELLOW}NEXT: Generate Reality keypair:${NC}"
  echo -e "  $XRAY_DIR/xray x25519"
  echo -e "  Then update privateKey in $CONFIG_DIR/xray-server.json"
  echo -e "  Then: systemctl restart xray"
}

main "$@"
