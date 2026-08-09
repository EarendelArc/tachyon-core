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
CONFIRM_PSK_ROTATION=false
TACHYON_PSK="${TACHYON_PSK:-}"
TACHYON_ROTATE_PSK="${TACHYON_ROTATE_PSK:-0}"
TACHYON_ALLOWED_TARGETS="${TACHYON_ALLOWED_TARGETS:-}"
ALLOWED_TARGET_INPUTS=()
ALLOWED_TARGET_OBJECTS=()
ALLOWED_TARGETS_JSON="[]"
COMPOSE_DIR="/opt/tachyon-docker"
OFFICIAL_GITHUB_REPO="EarendelArc/tachyon-core"
GITHUB_REPO="${TACHYON_CORE_REPO:-$OFFICIAL_GITHUB_REPO}"
GITHUB_CORE="https://api.github.com/repos/$GITHUB_REPO/releases"
GITHUB_API="https://api.github.com/repos/$GITHUB_REPO"
TACHYON_DEV_MODE="${TACHYON_DEV_MODE:-0}"
DOCKER_ENGINE_MAJOR=29
CONTAINERD_MAJOR=2
DOCKER_BUILDX_MAJOR=0
DOCKER_COMPOSE_MAJOR=5
DOCKER_APT_KEYRING="/etc/apt/keyrings/docker.asc"
DOCKER_APT_SOURCE="/etc/apt/sources.list.d/docker.sources"
DOCKER_APT_PREFERENCES="/etc/apt/preferences.d/tachyon-docker-ce"
DOCKER_APT_KEY_FINGERPRINT="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
TACHYON_BASE_IMAGE="debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241"
SYSTEMD_UNIT="/etc/systemd/system/tachyon-docker.service"
EXPECTED_PRERELEASE="true"
INSTALL_WORK_ROOT=""
TRANSACTION_DIR="$(dirname "$COMPOSE_DIR")/.tachyon-docker.transaction"
ACTIVE_TRANSACTION=false
PROC_ROOT="/proc"
DEPLOYMENT_HEALTH_TIMEOUT_SECONDS=120

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
  --confirm-psk-rotation       Required with TACHYON_ROTATE_PSK=1 when replacing
                               an existing deployment PSK
  --uninstall                  Remove Docker compose deployment and service
  -h, --help                   Show this help

ENV:
  TACHYON_PSK                  Existing shared TGP PSK; generated if omitted
  TACHYON_ROTATE_PSK=1         Explicitly request replacement of an existing PSK
  TACHYON_ALLOWED_TARGETS      Semicolon-separated relay ACL entries
  TACHYON_DEV_MODE=1           Permit a non-official TACHYON_CORE_REPO for development

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
      --confirm-psk-rotation) CONFIRM_PSK_ROTATION=true; shift ;;
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
  apt-get install -y -qq ca-certificates curl gnupg jq unzip
  success "Dependencies installed."
}

validate_repository_policy() {
  case "$TACHYON_DEV_MODE" in
    0|1) ;;
    *) die "TACHYON_DEV_MODE must be 0 or 1" ;;
  esac
  [[ "$GITHUB_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
    || die "TACHYON_CORE_REPO must be an exact GitHub owner/repository name"
  if [[ "$GITHUB_REPO" != "$OFFICIAL_GITHUB_REPO" ]]; then
    [[ "$TACHYON_DEV_MODE" == "1" ]] \
      || die "custom TACHYON_CORE_REPO is forbidden outside TACHYON_DEV_MODE=1"
    warn "DEVELOPMENT MODE: downloading an untrusted custom repository: $GITHUB_REPO"
  fi
}

cleanup_install_work() {
  [[ -z "$INSTALL_WORK_ROOT" ]] || rm -rf -- "$INSTALL_WORK_ROOT"
}

reject_docker_client_overrides() {
  local variable
  for variable in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH; do
    [[ -z "${!variable:-}" ]] \
      || die "$variable is forbidden; the installer only supports the local system Docker daemon"
  done
}

verify_local_docker_daemon() {
  reject_docker_client_overrides
  local context endpoint
  context=$(docker context show) || die "Unable to identify the active Docker context"
  [[ "$context" == "default" ]] \
    || die "Docker context must be default, got $context"
  endpoint=$(docker context inspect default --format '{{ (index .Endpoints "docker").Host }}') \
    || die "Unable to inspect the default Docker endpoint"
  [[ "$endpoint" == "unix:///var/run/docker.sock" ]] \
    || die "Docker endpoint must be unix:///var/run/docker.sock, got $endpoint"
  [[ -S /var/run/docker.sock ]] \
    || die "Local Docker socket /var/run/docker.sock is unavailable"
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
  local version selected=""
  while IFS= read -r version; do
    [[ -n "$version" ]] || continue
    if version_allowed "$package" "$version" && { [[ -z "$selected" ]] || dpkg --compare-versions "$version" gt "$selected"; }; then
      selected="$version"
    fi
  done
  [[ -n "$selected" ]] || return 1
  printf '%s\n' "$selected"
}

select_apt_version() {
  local package="$1"
  local versions selected
  versions=$(apt-cache madison "$package" | awk '{print $3}') \
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
  local fingerprints
  fingerprints=$(gpg --batch --show-keys --with-colons "$key_tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print toupper($10) }') \
    || { rm -f "$key_tmp"; die "Unable to inspect Docker apt signing key"; }
  grep -Fxq "$DOCKER_APT_KEY_FINGERPRINT" <<< "$fingerprints" \
    || { rm -f "$key_tmp"; die "Docker apt signing key fingerprint mismatch"; }
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
  verify_local_docker_daemon
  docker version --format '{{.Server.Version}}' >/dev/null \
    || die "Docker daemon is not reachable"
  docker compose version --short >/dev/null \
    || die "Docker Compose plugin is unavailable"
}

install_docker() {
  reject_docker_client_overrides
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

github_api_get() {
  local url="$1"
  local args=(--proto '=https' --tlsv1.2 -fsSL -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  curl "${args[@]}" "$url"
}

resolve_release_json() {
  local destination="$1"
  if [[ "$TACHYON_VERSION" == "latest" ]]; then
    local releases
    releases=$(mktemp)
    github_api_get "$GITHUB_CORE?per_page=100" > "$releases" \
      || { rm -f "$releases"; die "Unable to enumerate Tachyon releases"; }
    TACHYON_VERSION=$(jq -er --argjson prerelease "$EXPECTED_PRERELEASE" '
      [ .[] | select(.draft == false and .prerelease == $prerelease) ]
      | max_by(.published_at) | .tag_name
      | select(type == "string" and length > 0)
    ' "$releases") || { rm -f "$releases"; die "No release matches the required prerelease policy"; }
    rm -f "$releases"
  fi
  [[ "$TACHYON_VERSION" =~ ^v[0-9A-Za-z][0-9A-Za-z._-]*$ ]] \
    || die "Invalid Tachyon release tag"
  github_api_get "$GITHUB_CORE/tags/$TACHYON_VERSION" > "$destination" \
    || die "Unable to fetch exact release tag $TACHYON_VERSION"
}

validate_release_metadata() {
  local release_json="$1"
  jq -e --arg tag "$TACHYON_VERSION" --argjson prerelease "$EXPECTED_PRERELEASE" '
    .tag_name == $tag and
    .draft == false and
    .prerelease == $prerelease and
    .immutable == true and
    (.target_commitish | type == "string" and test("^[0-9a-fA-F]{40}$")) and
    (.assets | type == "array")
  ' "$release_json" >/dev/null || die "Release metadata violates the immutable prerelease contract"
  RELEASE_COMMIT=$(jq -er '.target_commitish | ascii_downcase' "$release_json") \
    || die "Release target commit is unavailable"
}

validate_annotated_tag_metadata() {
  local ref_json="$1"
  local tag_object_json="$2"
  local expected_commit="$3"
  jq -e '.object.type == "tag" and (.object.sha | test("^[0-9a-fA-F]{40}$"))' "$ref_json" >/dev/null \
    || die "Release tag must be an annotated tag object"
  local tag_commit
  tag_commit=$(jq -er '.object | select(.type == "commit") | .sha | ascii_downcase' "$tag_object_json") \
    || die "Annotated release tag does not target a commit"
  [[ "$tag_commit" == "$expected_commit" ]] \
    || die "Annotated tag commit does not match release target_commitish"
}

verify_release_identity() {
  local release_json="$1"
  validate_release_metadata "$release_json"
  local ref_json tag_object_json tag_object
  ref_json="$(dirname "$release_json")/tag-ref.json"
  tag_object_json="$(dirname "$release_json")/tag-object.json"
  github_api_get "$GITHUB_API/git/ref/tags/$TACHYON_VERSION" > "$ref_json" \
    || { rm -f "$ref_json" "$tag_object_json"; die "Unable to resolve release tag ref"; }
  tag_object=$(jq -er '.object | select(.type == "tag") | .sha | ascii_downcase' "$ref_json") \
    || { rm -f "$ref_json" "$tag_object_json"; die "Release tag must be an annotated tag object"; }
  github_api_get "$GITHUB_API/git/tags/$tag_object" > "$tag_object_json" \
    || { rm -f "$ref_json" "$tag_object_json"; die "Unable to inspect annotated release tag"; }
  validate_annotated_tag_metadata "$ref_json" "$tag_object_json" "$RELEASE_COMMIT" \
    || { rm -f "$ref_json" "$tag_object_json"; return 1; }
  rm -f "$ref_json" "$tag_object_json"
}

asset_metadata() {
  local release_json="$1"
  local asset_name="$2"
  local count
  count=$(jq --arg name "$asset_name" '[.assets[] | select(.name == $name)] | length' "$release_json")
  [[ "$count" == "1" ]] || die "Release must contain exactly one asset named $asset_name"
  jq -c --arg name "$asset_name" '.assets[] | select(.name == $name)' "$release_json"
}

download_verified_asset() {
  local metadata="$1"
  local destination="$2"
  local name url expected_digest expected_size actual_digest actual_size expected_prefix
  name=$(jq -er '.name' <<< "$metadata")
  expected_prefix="https://github.com/$GITHUB_REPO/releases/download/$TACHYON_VERSION/"
  url=$(jq -er --arg prefix "$expected_prefix" '.browser_download_url | select(startswith($prefix))' <<< "$metadata") \
    || die "Release asset $name has an invalid download URL"
  expected_digest=$(jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))' <<< "$metadata") \
    || die "Release asset $name has no immutable SHA-256 digest"
  expected_size=$(jq -er '.size | select(type == "number" and . > 0 and floor == .)' <<< "$metadata") \
    || die "Release asset $name has an invalid size"
  curl --proto '=https' --tlsv1.2 -fL --progress-bar -o "$destination" "$url" \
    || die "Unable to download release asset $name"
  actual_size=$(stat -c '%s' "$destination")
  [[ "$actual_size" == "$expected_size" ]] || die "Release asset size mismatch for $name"
  actual_digest="sha256:$(sha256sum "$destination" | awk '{print $1}')"
  [[ "$actual_digest" == "$expected_digest" ]] || die "Release asset digest mismatch for $name"
}

verify_archive_checksum() {
  local work_dir="$1"
  local asset_name="$2"
  local lines
  lines=$(awk -v name="$asset_name" '$2 == name { count++; line=$0 } END { if (count == 1) print line }' "$work_dir/SHA256SUMS.txt")
  [[ -n "$lines" ]] || die "SHA256SUMS.txt must contain exactly one checksum for $asset_name"
  printf '%s\n' "$lines" > "$work_dir/SHA256SUMS.asset"
  (cd "$work_dir" && sha256sum --check --strict SHA256SUMS.asset) \
    || die "Checksum verification failed for $asset_name"
}

read_existing_private_psk() {
  local config_path="$1"
  [[ -e "$config_path" ]] || return 1
  [[ -f "$config_path" && ! -L "$config_path" ]] \
    || die "Existing Tachyon config is not a regular private file"
  local mode owner
  mode=$(stat -c '%a' "$config_path")
  owner=$(stat -c '%u' "$config_path")
  (( (8#$mode & 077) == 0 )) || die "Existing Tachyon config is readable by group or others"
  [[ "$owner" == "0" || "$owner" == "65532" ]] \
    || die "Existing Tachyon config has an unexpected owner"
  jq -er '.mode == "server" and (.tgp.auth.psk | type == "string" and length >= 16) | select(.)' "$config_path" >/dev/null \
    || die "Existing Tachyon config is invalid; refusing to overwrite it"
  jq -er '.tgp.auth.psk' "$config_path"
}

ensure_tgp_psk() {
  local existing_psk=""
  if [[ -e "$COMPOSE_DIR/config/server.json" ]]; then
    existing_psk=$(read_existing_private_psk "$COMPOSE_DIR/config/server.json")
  fi
  case "$TACHYON_ROTATE_PSK" in
    0|1) ;;
    *) die "TACHYON_ROTATE_PSK must be 0 or 1" ;;
  esac

  local requested_psk="$TACHYON_PSK"
  TACHYON_PSK=$(select_tgp_psk "$existing_psk" "$requested_psk" "$TACHYON_ROTATE_PSK" "$CONFIRM_PSK_ROTATION")
  if [[ -n "$existing_psk" && "$TACHYON_ROTATE_PSK" == "0" ]]; then
    info "Preserving the existing private TGP PSK."
  elif [[ -n "$existing_psk" && "$TACHYON_ROTATE_PSK" == "1" ]]; then
    warn "Confirmed TGP PSK rotation will invalidate existing clients."
  fi
  [[ ${#TACHYON_PSK} -ge 16 ]] || die "TACHYON_PSK must be at least 16 characters"
  [[ "$TACHYON_PSK" =~ ^[A-Za-z0-9._~:-]+$ ]] || die "TACHYON_PSK contains characters unsafe for this installer"
}

select_tgp_psk() {
  local existing="$1"
  local requested="$2"
  local rotate="$3"
  local confirmed="$4"
  if [[ -n "$existing" && "$rotate" == "0" ]]; then
    [[ -z "$requested" || "$requested" == "$existing" ]] \
      || die "Refusing implicit PSK replacement; set TACHYON_ROTATE_PSK=1 and pass --confirm-psk-rotation"
    printf '%s\n' "$existing"
    return 0
  fi
  if [[ -n "$existing" && "$rotate" == "1" ]]; then
    [[ "$confirmed" == "true" ]] || die "PSK rotation requires --confirm-psk-rotation"
    [[ -n "$requested" ]] || requested=$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')
    [[ "$requested" != "$existing" ]] || die "Requested PSK rotation did not change the PSK"
    printf '%s\n' "$requested"
    return 0
  fi
  [[ "$rotate" == "0" ]] || die "PSK rotation was requested but no existing deployment is present"
  [[ -n "$requested" ]] || requested=$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')
  printf '%s\n' "$requested"
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
  local deployment_dir="$1"
  local evidence_dir="$2"
  local release_json="$evidence_dir/release.json"
  resolve_release_json "$release_json"
  verify_release_identity "$release_json"
  info "Installing tachyon-core $TACHYON_VERSION for Docker..."

  local arch asset_name archive metadata checksums_metadata entries
  arch=$(dpkg --print-architecture)
  asset_name="tachyon-core_${TACHYON_VERSION}_linux_${arch}.zip"
  archive="$evidence_dir/$asset_name"
  metadata=$(asset_metadata "$release_json" "$asset_name")
  checksums_metadata=$(asset_metadata "$release_json" "SHA256SUMS.txt")
  download_verified_asset "$metadata" "$archive"
  download_verified_asset "$checksums_metadata" "$evidence_dir/SHA256SUMS.txt"
  verify_archive_checksum "$evidence_dir" "$asset_name"
  entries=$(unzip -Z1 "$archive") || die "Unable to inspect Tachyon release archive"
  [[ $(grep -Fxc 'tachyon-core' <<< "$entries") -eq 1 ]] \
    || die "Release archive must contain exactly one root tachyon-core binary"
  if grep -Eq '(^/|(^|/)\.\.(/|$)|\\)' <<< "$entries"; then
    die "Release archive contains an unsafe path"
  fi
  install -d -m 0750 "$deployment_dir/bin"
  unzip -p "$archive" tachyon-core > "$deployment_dir/bin/tachyon-core"
  chmod 0555 "$deployment_dir/bin/tachyon-core"
  success "tachyon-core binary installed."
}

write_configs() {
  local deployment_dir="$1"
  ensure_tgp_psk
  collect_allowed_targets
  install -d -o 65532 -g 65532 -m 0750 "$deployment_dir/config" "$deployment_dir/logs"
  install -o 65532 -g 65532 -m 0400 /dev/null "$deployment_dir/config/server.json"
  cat > "$deployment_dir/config/server.json" <<JSON
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
  chown 65532:65532 "$deployment_dir/config/server.json"
  chmod 0400 "$deployment_dir/config/server.json"
  success "Config written."
  info "TGP PSK is stored in the private server config; it will not be printed."
  if [[ ${#ALLOWED_TARGET_OBJECTS[@]} -eq 0 ]]; then
    warn "Relay ACL is deny-all. Configure server.relay.allowed_targets before testing game UDP forwarding."
  fi
}

prepare_build_context() {
  local binary="$1"
  local context_dir="$2"
  mkdir -p "$context_dir/bin"
  chmod 0700 "$context_dir" "$context_dir/bin"
  cp "$binary" "$context_dir/bin/tachyon-core"
  chmod 0555 "$context_dir/bin/tachyon-core"
  cat > "$context_dir/Dockerfile" <<EOF
ARG TACHYON_BASE_IMAGE=$TACHYON_BASE_IMAGE
FROM \${TACHYON_BASE_IMAGE}
COPY --chown=65532:65532 --chmod=0555 bin/tachyon-core /opt/tachyon/tachyon-core
USER 65532:65532
ENTRYPOINT ["/opt/tachyon/tachyon-core"]
EOF
  cat > "$context_dir/.dockerignore" <<'EOF'
**
!Dockerfile
!.dockerignore
!bin/
!bin/tachyon-core
EOF
  local manifest
  manifest=$(cd "$context_dir" && find . -mindepth 1 -type f -printf '%P\n' | LC_ALL=C sort)
  [[ "$manifest" == $'.dockerignore\nDockerfile\nbin/tachyon-core' ]] \
    || die "Docker build context contains an unexpected file"
  [[ -z $(find "$context_dir" -type l -print -quit) ]] \
    || die "Docker build context contains a symlink"
  success "Minimal digest-pinned Docker build context prepared."
}

write_compose() {
  local deployment_dir="$1"
  local image="$2"
  cat > "$deployment_dir/docker-compose.yaml" <<YAML
services:
  tachyon-core:
    image: $image
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

write_systemd_unit() {
  local destination="$1"
  cat > "$destination" <<UNIT
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
}

validate_staged_contract() {
  local deployment_dir="$1"
  local config="$deployment_dir/config/server.json"
  local logs="$deployment_dir/logs"
  [[ $(stat -c '%u:%g:%a' "$config") == "65532:65532:400" ]] \
    || die "Staged config is not private and readable by container UID 65532"
  [[ $(stat -c '%u:%g' "$logs") == "65532:65532" && -w "$logs" ]] \
    || die "Staged logs directory is not writable by container UID 65532"
  grep -Fq 'network_mode: host' "$deployment_dir/docker-compose.yaml" \
    || die "Staged compose lost host networking"
  grep -Fq 'user: "65532:65532"' "$deployment_dir/docker-compose.yaml" \
    || die "Staged compose lost the non-root UID contract"
  grep -Fq -- '- NET_BIND_SERVICE' "$deployment_dir/docker-compose.yaml" \
    || die "Staged compose lost CAP_NET_BIND_SERVICE"
  grep -Fq "$COMPOSE_DIR/config/server.json:/etc/tachyon/server.json:ro" "$deployment_dir/docker-compose.yaml" \
    || die "Staged compose config mount is not read-only"
  grep -Fq "$COMPOSE_DIR/logs:/var/log/tachyon:rw" "$deployment_dir/docker-compose.yaml" \
    || die "Staged compose logs mount is not writable"
}

build_and_validate_staged_deployment() {
  local deployment_dir="$1"
  local context_dir="$2"
  local image="$3"
  docker build --pull --build-arg "TACHYON_BASE_IMAGE=$TACHYON_BASE_IMAGE" --tag "$image" "$context_dir"
  docker compose -f "$deployment_dir/docker-compose.yaml" config -q
  docker run --rm --network none --read-only --cap-drop ALL \
    --volume "$deployment_dir/config/server.json:/etc/tachyon/server.json:ro" \
    "$image" validate --config /etc/tachyon/server.json
  validate_staged_contract "$deployment_dir"
}

container_owns_udp_listener() {
  local container_pid="$1"
  local port="$2"
  [[ "$container_pid" =~ ^[0-9]+$ && "$container_pid" -gt 1 ]] || return 1
  [[ -d "$PROC_ROOT/$container_pid/fd" ]] || return 1
  local port_hex inode fd target
  port_hex=$(printf '%04X' "$port")
  while IFS= read -r inode; do
    [[ "$inode" =~ ^[0-9]+$ ]] || continue
    for fd in "$PROC_ROOT/$container_pid/fd"/*; do
      target=$(readlink "$fd" 2>/dev/null || true)
      [[ "$target" == "socket:[$inode]" ]] && return 0
    done
  done < <(awk -v port="$port_hex" '
    NR > 1 {
      split($2, local, ":")
      if (toupper(local[2]) == port && $4 == "07" && $10 ~ /^[0-9]+$/) print $10
    }
  ' "$PROC_ROOT/$container_pid/net/udp" "$PROC_ROOT/$container_pid/net/udp6" 2>/dev/null)
  return 1
}

verify_running_deployment() {
  local expected_image="$1"
  local expected_port="$2"
  local deadline=$((SECONDS + DEPLOYMENT_HEALTH_TIMEOUT_SECONDS))
  local compose_id container_id state health configured_image expected_image_id container_image service pid
  while (( SECONDS < deadline )); do
    compose_id=$(docker compose -f "$COMPOSE_DIR/docker-compose.yaml" ps -q tachyon-core 2>/dev/null || true)
    if [[ "$compose_id" =~ ^[0-9a-f]{12,64}$ ]]; then
      container_id=$(docker inspect --format '{{.Id}}' "$compose_id" 2>/dev/null || true)
      state=$(docker inspect --format '{{.State.Status}}' "$compose_id" 2>/dev/null || true)
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$compose_id" 2>/dev/null || true)
      configured_image=$(docker inspect --format '{{.Config.Image}}' "$compose_id" 2>/dev/null || true)
      container_image=$(docker inspect --format '{{.Image}}' "$compose_id" 2>/dev/null || true)
      service=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$compose_id" 2>/dev/null || true)
      pid=$(docker inspect --format '{{.State.Pid}}' "$compose_id" 2>/dev/null || true)
      expected_image_id=$(docker image inspect --format '{{.Id}}' "$expected_image" 2>/dev/null || true)
      if [[ "$container_id" =~ ^[0-9a-f]{64}$ && "$state" == "running" && "$health" == "healthy" && \
            "$configured_image" == "$expected_image" && "$container_image" == "$expected_image_id" && \
            "$service" == "tachyon-core" ]] && container_owns_udp_listener "$pid" "$expected_port"; then
        success "Verified healthy Tachyon container $container_id, image $expected_image, and owned UDP/$expected_port listener."
        return 0
      fi
      [[ "$state" != "exited" && "$state" != "dead" ]] \
        || { warn "Tachyon container entered terminal state $state before becoming healthy."; return 1; }
    fi
    sleep 1
  done
  warn "Timed out waiting for the expected healthy container and owned UDP/$expected_port listener."
  return 1
}

write_transaction_field() {
  local name="$1"
  local value="$2"
  [[ "$name" =~ ^[a-z_]+$ && "$value" != *$'\n'* ]] || return 1
  local temporary="$TRANSACTION_DIR/.$name.new.$$"
  printf '%s\n' "$value" > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$TRANSACTION_DIR/$name"
  sync -f "$TRANSACTION_DIR" 2>/dev/null || sync
}

read_transaction_field() {
  local name="$1"
  local path="$TRANSACTION_DIR/$name"
  [[ -f "$path" && ! -L "$path" ]] || return 1
  local value
  IFS= read -r value < "$path"
  printf '%s\n' "$value"
}

validate_transaction_journal() {
  [[ -d "$TRANSACTION_DIR" && ! -L "$TRANSACTION_DIR" ]] \
    || die "Pending Docker transaction journal is not a private directory: $TRANSACTION_DIR"
  [[ $(stat -c '%u:%a' "$TRANSACTION_DIR") == "$EUID:700" ]] \
    || die "Pending Docker transaction journal has unsafe ownership or permissions"
  local state enabled deployment_present unit_present phase
  state=$(read_transaction_field previous_state) || die "Transaction journal has no previous_state"
  enabled=$(read_transaction_field previous_enabled) || die "Transaction journal has no previous_enabled"
  deployment_present=$(read_transaction_field deployment_present) || die "Transaction journal has no deployment_present"
  unit_present=$(read_transaction_field unit_present) || die "Transaction journal has no unit_present"
  phase=$(read_transaction_field phase) || die "Transaction journal has no phase"
  [[ "$state" =~ ^(absent|active|inactive)$ ]] || die "Transaction journal previous_state is invalid"
  [[ "$enabled" =~ ^(enabled|disabled)$ ]] || die "Transaction journal previous_enabled is invalid"
  [[ "$deployment_present" =~ ^(true|false)$ ]] || die "Transaction journal deployment_present is invalid"
  [[ "$unit_present" =~ ^(true|false)$ ]] || die "Transaction journal unit_present is invalid"
  [[ "$phase" =~ ^(prepared|switching|old-backed-up|deployment-active|unit-active|committed)$ ]] \
    || die "Transaction journal phase is invalid"
}

initialize_transaction_journal() {
  local previous_state="$1"
  local previous_enabled="$2"
  [[ ! -e "$TRANSACTION_DIR" && ! -L "$TRANSACTION_DIR" ]] \
    || die "A Docker deployment transaction is already pending"
  local preparing="$TRANSACTION_DIR.preparing.$$"
  rm -rf -- "$preparing"
  install -d -m 0700 "$preparing" "$preparing/backup"
  printf '%s\n' "$previous_state" > "$preparing/previous_state"
  printf '%s\n' "$previous_enabled" > "$preparing/previous_enabled"
  if [[ -d "$COMPOSE_DIR" ]]; then printf 'true\n' > "$preparing/deployment_present"; else printf 'false\n' > "$preparing/deployment_present"; fi
  if [[ -f "$SYSTEMD_UNIT" ]]; then
    printf 'true\n' > "$preparing/unit_present"
    cp -a "$SYSTEMD_UNIT" "$preparing/backup/tachyon-docker.service"
  else
    printf 'false\n' > "$preparing/unit_present"
  fi
  printf 'prepared\n' > "$preparing/phase"
  chmod 0600 "$preparing/previous_state" "$preparing/previous_enabled" \
    "$preparing/deployment_present" "$preparing/unit_present" "$preparing/phase"
  sync -f "$preparing" 2>/dev/null || sync
  mv "$preparing" "$TRANSACTION_DIR"
  sync -f "$(dirname "$TRANSACTION_DIR")" 2>/dev/null || sync
}

restore_service_state() {
  local state="$1"
  local enabled="$2"
  if [[ "$state" == "absent" ]]; then
    systemctl disable tachyon-docker >/dev/null 2>&1 || true
    return 0
  fi
  if [[ "$enabled" == "enabled" ]]; then
    systemctl enable tachyon-docker >/dev/null 2>&1
  else
    systemctl disable tachyon-docker >/dev/null 2>&1
  fi
  if [[ "$state" == "active" ]]; then
    systemctl start tachyon-docker >/dev/null 2>&1
  else
    systemctl stop tachyon-docker >/dev/null 2>&1
  fi
}

rollback_pending_transaction() {
  validate_transaction_journal
  local backup_dir="$TRANSACTION_DIR/backup"
  local previous_state previous_enabled deployment_present unit_present phase
  previous_state=$(read_transaction_field previous_state)
  previous_enabled=$(read_transaction_field previous_enabled)
  deployment_present=$(read_transaction_field deployment_present)
  unit_present=$(read_transaction_field unit_present)
  phase=$(read_transaction_field phase)
  local rollback_failed=false
  warn "Deployment switch failed; restoring the previous deployment."
  if ! systemctl stop tachyon-docker >/dev/null 2>&1 && [[ "$previous_state" != "absent" ]]; then
    rollback_failed=true
  fi
  if [[ "$previous_state" == "absent" ]]; then
    systemctl disable tachyon-docker >/dev/null 2>&1 || true
  fi
  if [[ "$deployment_present" == "true" && -d "$backup_dir/deployment" && ! -d "$backup_dir/deployment/logs" ]]; then
    if [[ -d "$COMPOSE_DIR/logs" ]]; then
      mv "$COMPOSE_DIR/logs" "$backup_dir/deployment/logs" || rollback_failed=true
    fi
  fi
  if [[ "$deployment_present" == "true" ]]; then
    if [[ -d "$backup_dir/deployment" ]]; then
      rm -rf "$COMPOSE_DIR"
      mv "$backup_dir/deployment" "$COMPOSE_DIR" || rollback_failed=true
    elif [[ ! -d "$COMPOSE_DIR" ]]; then
      rollback_failed=true
    fi
  else
    rm -rf "$COMPOSE_DIR"
  fi
  if [[ "$unit_present" == "true" && -f "$backup_dir/tachyon-docker.service" ]]; then
    install -m 0644 "$backup_dir/tachyon-docker.service" "$SYSTEMD_UNIT.rollback" || rollback_failed=true
    mv -f "$SYSTEMD_UNIT.rollback" "$SYSTEMD_UNIT" || rollback_failed=true
  elif [[ "$unit_present" == "true" ]]; then
    rollback_failed=true
  else
    rm -f "$SYSTEMD_UNIT"
  fi
  rm -f "$SYSTEMD_UNIT.new" "$SYSTEMD_UNIT.rollback"
  systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=true
  restore_service_state "$previous_state" "$previous_enabled" || rollback_failed=true
  if [[ "$rollback_failed" == "false" ]]; then
    rm -rf -- "$TRANSACTION_DIR"
    sync -f "$(dirname "$TRANSACTION_DIR")" 2>/dev/null || sync
    ACTIVE_TRANSACTION=false
    success "Previous Docker deployment restored from transaction phase $phase."
    return 0
  fi
  warn "Rollback was incomplete; the persistent journal remains at $TRANSACTION_DIR."
  return 1
}

recover_pending_transaction() {
  [[ -e "$TRANSACTION_DIR" || -L "$TRANSACTION_DIR" ]] || return 0
  validate_transaction_journal
  local phase
  phase=$(read_transaction_field phase)
  if [[ "$phase" == "committed" ]]; then
    rm -rf -- "$TRANSACTION_DIR"
    success "Removed a completed Docker transaction journal left by an interrupted cleanup."
    return 0
  fi
  warn "Recovering interrupted Docker deployment transaction at phase $phase."
  rollback_pending_transaction \
    || die "Automatic Docker transaction recovery failed; refusing a new deployment"
}

on_installer_exit() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ "$ACTIVE_TRANSACTION" == "true" && -d "$TRANSACTION_DIR" ]]; then
    rollback_pending_transaction || status=1
  fi
  cleanup_install_work
  exit "$status"
}

on_installer_signal() {
  local name="$1"
  local status="$2"
  warn "Received $name during Docker deployment; rolling back before exit."
  exit "$status"
}

commit_deployment() {
  local staged_deployment="$1"
  local staged_unit="$2"
  local expected_image="$3"
  local expected_port="$4"
  local previous_state="absent"
  local previous_enabled="disabled"
  if [[ -f "$SYSTEMD_UNIT" || -d "$COMPOSE_DIR" ]]; then
    systemctl is-active --quiet tachyon-docker && previous_state="active" || previous_state="inactive"
    systemctl is-enabled --quiet tachyon-docker && previous_enabled="enabled" || previous_enabled="disabled"
  fi
  initialize_transaction_journal "$previous_state" "$previous_enabled"
  ACTIVE_TRANSACTION=true
  write_transaction_field phase switching

  if [[ "$previous_state" == "active" ]] && ! systemctl stop tachyon-docker; then
    die "Unable to stop the existing Tachyon Docker service; deployment was not changed"
  fi
  [[ ! -d "$COMPOSE_DIR" ]] || mv "$COMPOSE_DIR" "$TRANSACTION_DIR/backup/deployment"
  write_transaction_field phase old-backed-up

  mv "$staged_deployment" "$COMPOSE_DIR" \
    || die "Unable to atomically activate the staged deployment"
  write_transaction_field phase deployment-active
  if [[ -d "$TRANSACTION_DIR/backup/deployment/logs" ]]; then
    rm -rf "$staged_deployment/logs"
    rm -rf "$COMPOSE_DIR/logs"
    mv "$TRANSACTION_DIR/backup/deployment/logs" "$COMPOSE_DIR/logs"
  fi
  install -m 0644 "$staged_unit" "$SYSTEMD_UNIT.new" \
    && mv -f "$SYSTEMD_UNIT.new" "$SYSTEMD_UNIT" \
    && systemctl daemon-reload \
    || die "Unable to activate the staged systemd unit"
  write_transaction_field phase unit-active

  systemctl start tachyon-docker \
    || die "New Docker service failed to start"
  systemctl is-active --quiet tachyon-docker \
    || die "New Docker service did not remain active"
  verify_running_deployment "$expected_image" "$expected_port" \
    || die "New Docker deployment failed its container identity, health, or UDP listener gate"

  if [[ "$previous_state" == "inactive" ]]; then
    systemctl stop tachyon-docker || die "Unable to restore the previous inactive service state"
  fi
  if [[ "$previous_enabled" == "enabled" || "$previous_state" == "absent" ]]; then
    systemctl enable tachyon-docker >/dev/null \
      || die "Unable to enable the verified Tachyon Docker service"
  else
    systemctl disable tachyon-docker >/dev/null \
      || die "Unable to preserve the previous disabled service state"
  fi
  if [[ "$previous_state" == "inactive" ]]; then
    systemctl is-active --quiet tachyon-docker \
      && die "Tachyon Docker service should have returned to inactive state"
    success "Verified deployment updated; the previously inactive service remains inactive."
  else
    systemctl is-active --quiet tachyon-docker \
      || die "Verified Tachyon Docker service is unexpectedly inactive"
    success "Verified Docker service started on UDP/$expected_port."
  fi

  sync -f "$COMPOSE_DIR" 2>/dev/null || sync
  sync -f "$(dirname "$SYSTEMD_UNIT")" 2>/dev/null || sync
  write_transaction_field phase committed
  ACTIVE_TRANSACTION=false
  rm -rf -- "$TRANSACTION_DIR"
  sync -f "$(dirname "$TRANSACTION_DIR")" 2>/dev/null || sync
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
  trap on_installer_exit EXIT
  trap 'on_installer_signal INT 130' INT
  trap 'on_installer_signal TERM 143' TERM
  trap 'on_installer_signal HUP 129' HUP
  reject_docker_client_overrides
  [[ ! -L "$COMPOSE_DIR" ]] || die "Refusing symlinked deployment directory"
  [[ ! -L "$SYSTEMD_UNIT" ]] || die "Refusing symlinked systemd unit"
  recover_pending_transaction
  if [[ "$UNINSTALL" == "true" ]]; then
    verify_local_docker_daemon
    uninstall
    exit 0
  fi
  validate_repository_policy
  if [[ -e "$COMPOSE_DIR/logs" ]]; then
    [[ -d "$COMPOSE_DIR/logs" && ! -L "$COMPOSE_DIR/logs" ]] \
      || die "Existing logs path is not a regular directory"
    [[ $(stat -c '%u:%g' "$COMPOSE_DIR/logs") == "65532:65532" ]] \
      || die "Existing logs directory has an unexpected owner"
  fi
  install_deps
  install_docker
  install -d -m 0755 "$(dirname "$COMPOSE_DIR")"
  local work_root staged_deployment evidence_dir context_dir staged_unit image
  work_root=$(mktemp -d "$(dirname "$COMPOSE_DIR")/.tachyon-install.XXXXXX")
  chmod 0700 "$work_root"
  INSTALL_WORK_ROOT="$work_root"
  staged_deployment="$work_root/deployment"
  evidence_dir="$work_root/release-evidence"
  context_dir="$work_root/build-context"
  staged_unit="$work_root/tachyon-docker.service"
  install -d -m 0700 "$staged_deployment" "$evidence_dir"

  install_tachyon_binary "$staged_deployment" "$evidence_dir"
  write_configs "$staged_deployment"
  image="tachyon-core-local:${RELEASE_COMMIT:0:12}"
  prepare_build_context "$staged_deployment/bin/tachyon-core" "$context_dir"
  write_compose "$staged_deployment" "$image"
  write_systemd_unit "$staged_unit"
  build_and_validate_staged_deployment "$staged_deployment" "$context_dir" "$image"
  commit_deployment "$staged_deployment" "$staged_unit" "$image" "$PORT"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
