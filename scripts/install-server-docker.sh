#!/usr/bin/env bash
# Tachyon Core TGP server Docker deployment.
#
# This deployment is TGP-only and does not run Xray. Prism/Xray owns TCP proxy
# orchestration on the desktop side.

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
COMPOSE_DIR="/opt/tachyon-docker"
GITHUB_REPO="${TACHYON_CORE_REPO:-EarendelArc/tachyon-core}"
GITHUB_CORE="https://api.github.com/repos/$GITHUB_REPO/releases"
DOCKER_ENGINE_MAJOR=29
CONTAINERD_MAJOR=2
DOCKER_BUILDX_MAJOR=0
DOCKER_COMPOSE_MAJOR=5
DOCKER_APT_KEYRING="/etc/apt/keyrings/docker.asc"
DOCKER_APT_SOURCE="/etc/apt/sources.list.d/docker.sources"
DOCKER_APT_PREFERENCES="/etc/apt/preferences.d/tachyon-docker-ce"
TACHYON_BASE_IMAGE="debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241"

usage() {
  cat <<'USAGE'
Tachyon Core Docker TGP server deployment for Debian / Ubuntu.

USAGE:
  sudo bash scripts/install-server-docker.sh [options]

OPTIONS:
  --port PORT                  UDP listen port for Tachyon TGP (default: 443)
  --version TAG|latest         Release tag to install (default: latest)
  --allow-target SPEC          Relay ACL entry; repeatable. Example:
                               cidr=198.51.100.0/24,ports=27015-27050
  --uninstall                  Remove Docker compose deployment and service
  -h, --help                   Show this help

ENV:
  TACHYON_PSK                  Existing shared TGP PSK; generated if omitted
  TACHYON_ALLOWED_TARGETS      Semicolon-separated relay ACL entries

Security notes:
  This deployment intentionally uses host networking to avoid Docker NAT/userland
  proxy jitter on latency-sensitive UDP. The container is still hardened with a
  read-only root filesystem, no-new-privileges, dropped capabilities, and only
  CAP_NET_BIND_SERVICE restored for low-port UDP binding. Configure host/cloud
  firewalls separately; this script does not change firewall rules.
USAGE
}

require_option_value() {
  local option="$1"
  if [[ $# -lt 2 || "${2:-}" == --* ]]; then
    die "$option requires a value"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port)
        require_option_value "$@"
        PORT="$2"
        shift 2
        ;;
      --version)
        require_option_value "$@"
        TACHYON_VERSION="$2"
        shift 2
        ;;
      --allow-target)
        require_option_value "$@"
        ALLOWED_TARGET_INPUTS+=("$2")
        shift 2
        ;;
      --uninstall) UNINSTALL=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
}

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

install_deps() {
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl jq unzip
  success "Dependencies installed."
}

version_allowed() {
  local package="$1"
  local version="$2"
  case "$package" in
    docker-ce|docker-ce-cli) [[ "$version" =~ ^5:${DOCKER_ENGINE_MAJOR}\. ]] ;;
    containerd.io) [[ "$version" =~ ^${CONTAINERD_MAJOR}\. ]] ;;
    docker-buildx-plugin) [[ "$version" =~ ^${DOCKER_BUILDX_MAJOR}\. ]] ;;
    docker-compose-plugin) [[ "$version" =~ ^${DOCKER_COMPOSE_MAJOR}\. ]] ;;
    *) return 1 ;;
  esac
}

select_version_from_list() {
  local package="$1"
  local version
  while IFS= read -r version; do
    [[ -n "$version" ]] || continue
    if version_allowed "$package" "$version"; then
      printf '%s\n' "$version"
      return 0
    fi
  done
  return 1
}

select_apt_version() {
  local package="$1"
  local versions selected
  versions=$(apt-cache madison "$package" | awk '{print $3}' | sort -Vr) \
    || die "Unable to enumerate Docker package versions for $package"
  selected=$(select_version_from_list "$package" <<< "$versions") \
    || die "No supported $package version is available from the configured stable repository"
  printf '%s\n' "$selected"
}

verify_supported_docker_host() {
  [[ -r /etc/os-release ]] || die "Missing /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  local distro="${ID:-}"
  local version="${VERSION_ID:-}"
  case "$distro:$version" in
    debian:11|debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:25.10|ubuntu:26.04) ;;
    *) die "Unsupported Docker host $distro $version; use a Docker-supported Debian/Ubuntu release" ;;
  esac
  local architecture
  architecture=$(dpkg --print-architecture)
  case "$architecture" in
    amd64|arm64) ;;
    *) die "No Tachyon release asset is supported for Debian architecture $architecture" ;;
  esac
  DOCKER_REPO_OS="$distro"
  DOCKER_REPO_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
  [[ -n "$DOCKER_REPO_CODENAME" ]] || die "Docker repository codename is unavailable"
}

refuse_conflicting_docker_packages() {
  local package
  for package in docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc; do
    if dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii'; then
      die "Conflicting package $package is installed; remove it explicitly before installing Docker CE"
    fi
  done
}

configure_docker_repository() {
  verify_supported_docker_host
  install -m 0755 -d /etc/apt/keyrings
  local key_tmp
  key_tmp=$(mktemp)
  if ! curl --proto '=https' --tlsv1.2 -fsSL \
    "https://download.docker.com/linux/$DOCKER_REPO_OS/gpg" -o "$key_tmp"; then
    rm -f "$key_tmp"
    die "Unable to download Docker's official apt signing key"
  fi
  [[ -s "$key_tmp" ]] || { rm -f "$key_tmp"; die "Docker apt signing key is empty"; }
  install -m 0644 "$key_tmp" "$DOCKER_APT_KEYRING"
  rm -f "$key_tmp"
  cat > "$DOCKER_APT_SOURCE" <<EOF
Types: deb
URIs: https://download.docker.com/linux/$DOCKER_REPO_OS
Suites: $DOCKER_REPO_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: $DOCKER_APT_KEYRING
EOF
  cat > "$DOCKER_APT_PREFERENCES" <<EOF
Package: docker-ce docker-ce-cli
Pin: version 5:${DOCKER_ENGINE_MAJOR}.*
Pin-Priority: 1001

Package: containerd.io
Pin: version ${CONTAINERD_MAJOR}.*
Pin-Priority: 1001

Package: docker-buildx-plugin
Pin: version ${DOCKER_BUILDX_MAJOR}.*
Pin-Priority: 1001

Package: docker-compose-plugin
Pin: version ${DOCKER_COMPOSE_MAJOR}.*
Pin-Priority: 1001

Package: docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
Pin: origin "download.docker.com"
Pin-Priority: -1
EOF
  apt-get update -qq
}

verify_installed_docker_policy() {
  local package version
  for package in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; do
    version=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null) \
      || die "Required Docker package $package is not installed"
    version_allowed "$package" "$version" \
      || die "Installed $package version $version is outside the supported major policy"
  done
  docker version --format '{{.Server.Version}}' >/dev/null \
    || die "Docker daemon is not reachable"
  docker compose version --short >/dev/null \
    || die "Docker Compose plugin is unavailable"
}

install_docker() {
  refuse_conflicting_docker_packages
  configure_docker_repository
  local engine_version cli_version containerd_version buildx_version compose_version
  engine_version=$(select_apt_version docker-ce)
  cli_version=$(select_apt_version docker-ce-cli)
  [[ "$engine_version" == "$cli_version" ]] \
    || die "docker-ce and docker-ce-cli resolved to different versions"
  containerd_version=$(select_apt_version containerd.io)
  buildx_version=$(select_apt_version docker-buildx-plugin)
  compose_version=$(select_apt_version docker-compose-plugin)
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    "docker-ce=$engine_version" \
    "docker-ce-cli=$cli_version" \
    "containerd.io=$containerd_version" \
    "docker-buildx-plugin=$buildx_version" \
    "docker-compose-plugin=$compose_version"
  systemctl enable --now docker
  verify_installed_docker_policy
  success "Docker CE installed from the official stable apt repository with exact package versions."
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
  ensure_tgp_psk
  collect_allowed_targets
  install -d -m 0750 "$COMPOSE_DIR/config" "$COMPOSE_DIR/logs"
  chown 65532:65532 "$COMPOSE_DIR/config" "$COMPOSE_DIR/logs"
  install -o 65532 -g 65532 -m 0400 /dev/null "$COMPOSE_DIR/config/server.json"
  cat > "$COMPOSE_DIR/config/server.json" <<JSON
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
    "log_file": "/var/log/tachyon/tachyon-core.log",
    "metrics_addr": "127.0.0.1:19090"
  }
}
JSON
  chown 65532:65532 "$COMPOSE_DIR/config/server.json"
  chmod 0400 "$COMPOSE_DIR/config/server.json"
  success "Config written."
  info "TGP PSK saved in $COMPOSE_DIR/config/server.json; copy it into the Prism Tachyon server profile."
  if [[ ${#ALLOWED_TARGET_OBJECTS[@]} -eq 0 ]]; then
    warn "Relay ACL is deny-all. Edit $COMPOSE_DIR/config/server.json server.relay.allowed_targets before testing game UDP forwarding."
  fi
}

write_dockerfile() {
  cat > "$COMPOSE_DIR/Dockerfile" <<EOF
ARG TACHYON_BASE_IMAGE=$TACHYON_BASE_IMAGE
FROM \${TACHYON_BASE_IMAGE}
COPY --chown=65532:65532 --chmod=0555 bin/tachyon-core /opt/tachyon/tachyon-core
USER 65532:65532
ENTRYPOINT ["/opt/tachyon/tachyon-core"]
EOF
  success "Digest-pinned Dockerfile written."
}

write_compose() {
  cat > "$COMPOSE_DIR/docker-compose.yaml" <<YAML
services:
  tachyon-core:
    image: tachyon-core-local:preview
    build:
      context: $COMPOSE_DIR
      dockerfile: Dockerfile
      args:
        TACHYON_BASE_IMAGE: $TACHYON_BASE_IMAGE
    container_name: tachyon-core
    restart: unless-stopped
    # Host networking avoids Docker NAT/userland proxy jitter for latency-sensitive UDP.
    # Risk is reduced by read-only rootfs, no-new-privileges, and a single restored cap.
    network_mode: host
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m
      - /run:rw,noexec,nosuid,nodev,size=8m
    pids_limit: 512
    user: "65532:65532"
    volumes:
      - $COMPOSE_DIR/config/server.json:/etc/tachyon/server.json:ro
      - $COMPOSE_DIR/logs:/var/log/tachyon:rw
    command: ["run", "--config", "/etc/tachyon/server.json"]
    healthcheck:
      test: [ "CMD", "/opt/tachyon/tachyon-core", "validate", "--config", "/etc/tachyon/server.json" ]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
YAML
  success "docker-compose.yaml written."
}

start_services() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yaml" build --pull
  cat > /etc/systemd/system/tachyon-docker.service <<UNIT
[Unit]
Description=Tachyon Core Docker TGP relay
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=$COMPOSE_DIR
ExecStartPre=/usr/bin/docker compose -f $COMPOSE_DIR/docker-compose.yaml config -q
ExecStart=/usr/bin/docker compose -f $COMPOSE_DIR/docker-compose.yaml up --remove-orphans
ExecStop=/usr/bin/docker compose -f $COMPOSE_DIR/docker-compose.yaml down
Restart=on-failure
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=60
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now tachyon-docker
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
  parse_args "$@"
  validate_listen_port "$PORT"
  check_root
  if [[ "$UNINSTALL" == "true" ]]; then
    uninstall
    exit 0
  fi
  install_deps
  install_docker
  install_tachyon_binary
  write_configs
  write_dockerfile
  write_compose
  start_services
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
