#!/usr/bin/env bash
# =============================================================================
# Tachyon Core — Server Mode Docker Installer
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

DOMAIN=""; EMAIL=""; UUID_VAL=""; PORT=443
TACHYON_VERSION="latest"; XRAY_VERSION="latest"; UNINSTALL=false
XRAY_INTERNAL_PORT=18443
COMPOSE_DIR="/opt/tachyon-docker"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)        DOMAIN="$2";          shift 2 ;;
    --email)         EMAIL="$2";           shift 2 ;;
    --uuid)          UUID_VAL="$2";        shift 2 ;;
    --port)          PORT="$2";            shift 2 ;;
    --version)       TACHYON_VERSION="$2"; shift 2 ;;
    --xray-version)  XRAY_VERSION="$2";   shift 2 ;;
    --uninstall)     UNINSTALL=true;       shift   ;;
    *) die "Unknown: $1" ;;
  esac
done

check_root() { [[ $EUID -eq 0 ]] || die "Run as root."; }
check_args() { [[ "$UNINSTALL" == "true" ]] && return; [[ -n "$DOMAIN" ]] || die "--domain required"; [[ -n "$EMAIL" ]] || die "--email required"; }

install_docker() {
  command -v docker &>/dev/null && { info "Docker already installed."; return; }
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  success "Docker installed."
}

obtain_cert() {
  apt-get install -y -qq socat curl
  [[ -f "$HOME/.acme.sh/acme.sh" ]] || curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
  mkdir -p "$COMPOSE_DIR/certs" "$COMPOSE_DIR/config" "$COMPOSE_DIR/logs"
  "$HOME/.acme.sh/acme.sh" --issue -d "$DOMAIN" --standalone --keylength ec-256 || warn "Cert may already exist."
  "$HOME/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" --ecc \
    --cert-file "$COMPOSE_DIR/certs/cert.pem" \
    --key-file  "$COMPOSE_DIR/certs/key.pem" \
    --fullchain-file "$COMPOSE_DIR/certs/fullchain.pem" \
    --reloadcmd "docker compose -f $COMPOSE_DIR/docker-compose.yaml restart 2>/dev/null || true"
  success "TLS cert ready."
}

write_configs() {
  [[ -n "$UUID_VAL" ]] || UUID_VAL=$(cat /proc/sys/kernel/random/uuid)
  # xray-server.json
  cat > "$COMPOSE_DIR/config/xray-server.json" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "127.0.0.1", "port": $XRAY_INTERNAL_PORT, "protocol": "vless",
    "settings": { "clients": [{ "id": "$UUID_VAL", "flow": "xtls-rprx-vision" }], "decryption": "none" },
    "streamSettings": { "network": "tcp", "security": "reality",
      "realitySettings": { "dest": "www.apple.com:443", "serverNames": ["$DOMAIN"],
        "privateKey": "__REPLACE_ME__", "shortIds": ["$(openssl rand -hex 4)"] } }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
JSON
  # tachyon-core server.yaml
  cat > "$COMPOSE_DIR/config/server.yaml" <<YAML
mode: server
server:
  listen: ":$PORT"
  tls:
    cert: /etc/tachyon/certs/fullchain.pem
    key:  /etc/tachyon/certs/key.pem
  xray_backend:
    addr: "127.0.0.1:$XRAY_INTERNAL_PORT"
  relay:
    dial_timeout: 5s
    idle_timeout: 60s
tgp:
  fec: { data_shards: 4, parity_shards: 2, group_timeout: 20ms }
  pacing: { initial_rate_pps: 128, max_rate_pps: 1000 }
  connection_migration: true
  multipath: true
observability:
  log_level: info
  log_file: /var/log/tachyon/tachyon-core.log
  metrics_addr: "127.0.0.1:19090"
YAML
  success "Configs written."
}

write_compose() {
  cat > "$COMPOSE_DIR/docker-compose.yaml" <<YAML
version: "3.9"
# Both services use host networking so they share the loopback interface.
# xray listens on 127.0.0.1:$XRAY_INTERNAL_PORT (not exposed externally).
# tachyon-core listens on :$PORT (TCP+UDP, exposed to internet).
services:
  xray:
    image: teddysun/xray:$XRAY_VERSION
    container_name: tachyon-xray
    restart: unless-stopped
    network_mode: host
    volumes:
      - $COMPOSE_DIR/config/xray-server.json:/etc/xray/config.json:ro
      - $COMPOSE_DIR/logs:/var/log/tachyon
    command: ["xray", "run", "-config", "/etc/xray/config.json"]
    healthcheck:
      test: ["CMD", "nc", "-z", "127.0.0.1", "$XRAY_INTERNAL_PORT"]
      interval: 30s
      timeout: 5s
      retries: 3

  tachyon-core:
    image: ghcr.io/tachyon-space/tachyon-core:$TACHYON_VERSION
    container_name: tachyon-core
    restart: unless-stopped
    network_mode: host
    depends_on:
      xray:
        condition: service_healthy
    volumes:
      - $COMPOSE_DIR/config/server.yaml:/etc/tachyon/server.yaml:ro
      - $COMPOSE_DIR/certs:/etc/tachyon/certs:ro
      - $COMPOSE_DIR/logs:/var/log/tachyon
    command: ["tachyon-core", "run", "--config", "/etc/tachyon/server.yaml"]
    ulimits:
      nofile: { soft: 1048576, hard: 1048576 }
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:19090/metrics"]
      interval: 30s
      timeout: 5s
      retries: 3
YAML
  success "docker-compose.yaml written."
}

start_services() {
  info "Pulling images and starting..."
  docker compose -f "$COMPOSE_DIR/docker-compose.yaml" pull --quiet
  docker compose -f "$COMPOSE_DIR/docker-compose.yaml" up -d
  # Systemd unit for auto-start on reboot
  cat > /etc/systemd/system/tachyon-docker.service <<UNIT
[Unit]
Description=Tachyon Core Docker
After=docker.service network-online.target
Requires=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$COMPOSE_DIR
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload && systemctl enable tachyon-docker
  success "Services started."
}

uninstall() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yaml" down -v 2>/dev/null || true
  systemctl disable --now tachyon-docker 2>/dev/null || true
  rm -f /etc/systemd/system/tachyon-docker.service && systemctl daemon-reload
  rm -rf "$COMPOSE_DIR"
  success "Docker deployment removed."
}

main() {
  check_root; check_args
  [[ "$UNINSTALL" == "true" ]] && { uninstall; exit 0; }
  install_docker; obtain_cert; write_configs; write_compose; start_services
  echo -e "\n${GREEN}══ Docker Deployment Complete ═════════════════════${NC}"
  echo -e "  UUID   : ${CYAN}$UUID_VAL${NC}"
  echo -e "  Domain : ${CYAN}$DOMAIN${NC}"
  warn "NEXT: docker exec tachyon-xray xray x25519"
  warn "      Update privateKey in $COMPOSE_DIR/config/xray-server.json"
  warn "      docker compose -f $COMPOSE_DIR/docker-compose.yaml restart xray"
}

main "$@"
