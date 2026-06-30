#!/usr/bin/env bash
# Tachyon Core TGP server Docker deployment.
#
# This deployment is TGP-only and does not run Xray. Prism/Xray owns TCP proxy
# orchestration on the desktop side.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
die()     { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

PORT=443
TACHYON_VERSION="latest"
UNINSTALL=false
COMPOSE_DIR="/opt/tachyon-docker"

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

install_docker() {
  command -v docker &>/dev/null && { info "Docker already installed."; return; }
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  success "Docker installed."
}

write_configs() {
  mkdir -p "$COMPOSE_DIR/config" "$COMPOSE_DIR/logs"
  cat > "$COMPOSE_DIR/config/server.json" <<JSON
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
    "multipath": true,
    "handshake_timeout": "5s",
    "session_idle_timeout": "300s"
  },
  "observability": {
    "log_level": "info",
    "log_file": "/var/log/tachyon/tachyon-core.log",
    "metrics_addr": "127.0.0.1:19090"
  }
}
JSON
  success "Config written."
}

write_compose() {
  cat > "$COMPOSE_DIR/docker-compose.yaml" <<YAML
services:
  tachyon-core:
    image: ghcr.io/tachyon-space/tachyon-core:$TACHYON_VERSION
    container_name: tachyon-core
    restart: unless-stopped
    network_mode: host
    volumes:
      - $COMPOSE_DIR/config/server.json:/etc/tachyon/server.json:ro
      - $COMPOSE_DIR/logs:/var/log/tachyon
    command: ["tachyon-core", "run", "--config", "/etc/tachyon/server.json"]
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
YAML
  success "docker-compose.yaml written."
}

start_services() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yaml" pull --quiet
  docker compose -f "$COMPOSE_DIR/docker-compose.yaml" up -d
  cat > /etc/systemd/system/tachyon-docker.service <<UNIT
[Unit]
Description=Tachyon Core Docker TGP relay
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
  systemctl daemon-reload
  systemctl enable tachyon-docker
  success "Docker service started on UDP/$PORT."
}

uninstall() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yaml" down -v 2>/dev/null || true
  systemctl disable --now tachyon-docker 2>/dev/null || true
  rm -f /etc/systemd/system/tachyon-docker.service
  systemctl daemon-reload
  rm -rf "$COMPOSE_DIR"
  success "Docker deployment removed."
}

main() {
  check_root
  if [[ "$UNINSTALL" == "true" ]]; then
    uninstall
    exit 0
  fi
  install_docker
  write_configs
  write_compose
  start_services
}

main "$@"
