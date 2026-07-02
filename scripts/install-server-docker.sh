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

install_docker() {
  command -v docker &>/dev/null && { info "Docker already installed."; return; }
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  success "Docker installed."
}

install_deps() {
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl jq unzip
  success "Dependencies installed."
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

install_tachyon_binary() {
  [[ "$TACHYON_VERSION" == "latest" ]] && TACHYON_VERSION=$(resolve_latest "$GITHUB_CORE")
  info "Installing tachyon-core $TACHYON_VERSION for Docker..."

  arch=$(dpkg --print-architecture)
  asset_name="tachyon-core_${TACHYON_VERSION}_linux_${arch}.zip"
  url=$(get_asset_url "$GITHUB_CORE" "$TACHYON_VERSION" "$asset_name")
  checksums_url=$(get_asset_url "$GITHUB_CORE" "$TACHYON_VERSION" "SHA256SUMS.txt")
  [[ -n "$url" ]] || die "No tachyon-core asset for linux_${arch}"
  [[ -n "$checksums_url" ]] || die "No SHA256SUMS.txt asset for $TACHYON_VERSION"

  mkdir -p "$COMPOSE_DIR/bin"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  curl -fL --progress-bar -o "$tmp/$asset_name" "$url"
  curl -fsSL -o "$tmp/SHA256SUMS.txt" "$checksums_url"
  verify_archive_checksum "$tmp" "$asset_name"
  unzip -q "$tmp/$asset_name" -d "$tmp"
  install -m 755 "$tmp/tachyon-core" "$COMPOSE_DIR/bin/tachyon-core"
  success "tachyon-core binary installed."
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
    "multipath": false,
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
    image: debian:bookworm-slim
    container_name: tachyon-core
    restart: unless-stopped
    network_mode: host
    volumes:
      - $COMPOSE_DIR/bin/tachyon-core:/opt/tachyon/tachyon-core:ro
      - $COMPOSE_DIR/config/server.json:/etc/tachyon/server.json:ro
      - $COMPOSE_DIR/logs:/var/log/tachyon
    command: ["/opt/tachyon/tachyon-core", "run", "--config", "/etc/tachyon/server.json"]
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
  install_deps
  install_docker
  install_tachyon_binary
  write_configs
  write_compose
  start_services
}

main "$@"
