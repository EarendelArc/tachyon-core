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

restore_service_state() {
  local state="$1"
  local enabled="$2"
  [[ "$state" != "absent" ]] || return 0
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

rollback_deployment() {
  local backup_dir="$1"
  local previous_state="$2"
  local previous_enabled="$3"
  local staged_deployment="$4"
  local rollback_failed=false
  warn "Deployment switch failed; restoring the previous deployment."
  if ! systemctl stop tachyon-docker >/dev/null 2>&1 && [[ "$previous_state" != "absent" ]]; then
    rollback_failed=true
  fi
  if [[ -d "$backup_dir/deployment" && ! -d "$backup_dir/deployment/logs" ]]; then
    if [[ -d "$COMPOSE_DIR/logs" ]]; then
      mv "$COMPOSE_DIR/logs" "$backup_dir/deployment/logs" || rollback_failed=true
    elif [[ -d "$staged_deployment/logs" ]]; then
      mv "$staged_deployment/logs" "$backup_dir/deployment/logs" || rollback_failed=true
    fi
  fi
  rm -rf "$COMPOSE_DIR"
  [[ ! -d "$backup_dir/deployment" ]] || mv "$backup_dir/deployment" "$COMPOSE_DIR" || rollback_failed=true
  if [[ -f "$backup_dir/tachyon-docker.service" ]]; then
    install -m 0644 "$backup_dir/tachyon-docker.service" "$SYSTEMD_UNIT.rollback" || rollback_failed=true
    mv -f "$SYSTEMD_UNIT.rollback" "$SYSTEMD_UNIT" || rollback_failed=true
  else
    rm -f "$SYSTEMD_UNIT"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=true
  restore_service_state "$previous_state" "$previous_enabled" || rollback_failed=true
  [[ "$rollback_failed" == "false" ]] \
    || die "Rollback was incomplete; inspect $COMPOSE_DIR and $SYSTEMD_UNIT before retrying"
}

commit_deployment() {
  local staged_deployment="$1"
  local staged_unit="$2"
  local work_root="$3"
  local backup_dir="$work_root/backup"
  local previous_state="absent"
  local previous_enabled="disabled"
  install -d -m 0700 "$backup_dir"
  if [[ -f "$SYSTEMD_UNIT" || -d "$COMPOSE_DIR" ]]; then
    systemctl is-active --quiet tachyon-docker && previous_state="active" || previous_state="inactive"
    systemctl is-enabled --quiet tachyon-docker && previous_enabled="enabled" || previous_enabled="disabled"
  fi

  if [[ "$previous_state" == "active" ]] && ! systemctl stop tachyon-docker; then
    die "Unable to stop the existing Tachyon Docker service; deployment was not changed"
  fi
  [[ ! -d "$COMPOSE_DIR" ]] || mv "$COMPOSE_DIR" "$backup_dir/deployment"
  if [[ -f "$SYSTEMD_UNIT" ]]; then
    cp -a "$SYSTEMD_UNIT" "$backup_dir/tachyon-docker.service"
  fi
  if [[ -d "$backup_dir/deployment/logs" ]]; then
    rm -rf "$staged_deployment/logs"
    mv "$backup_dir/deployment/logs" "$staged_deployment/logs"
  fi

  if ! mv "$staged_deployment" "$COMPOSE_DIR"; then
    rollback_deployment "$backup_dir" "$previous_state" "$previous_enabled" "$staged_deployment"
    die "Unable to atomically activate the staged deployment"
  fi
  if ! install -m 0644 "$staged_unit" "$SYSTEMD_UNIT.new" || ! mv -f "$SYSTEMD_UNIT.new" "$SYSTEMD_UNIT" || ! systemctl daemon-reload; then
    rollback_deployment "$backup_dir" "$previous_state" "$previous_enabled" "$staged_deployment"
    die "Unable to activate the staged systemd unit"
  fi

  if [[ "$previous_state" == "inactive" ]]; then
    if ! restore_service_state "inactive" "$previous_enabled"; then
      rollback_deployment "$backup_dir" "$previous_state" "$previous_enabled" "$staged_deployment"
      die "Unable to preserve the inactive service state; previous deployment restored"
    fi
    success "Deployment updated; the previously inactive service remains inactive."
  else
    local activation_failed=false
    if [[ "$previous_state" == "active" && "$previous_enabled" == "disabled" ]]; then
      systemctl disable tachyon-docker >/dev/null 2>&1 || activation_failed=true
      systemctl start tachyon-docker || activation_failed=true
    else
      systemctl enable --now tachyon-docker || activation_failed=true
    fi
    systemctl is-active --quiet tachyon-docker || activation_failed=true
    if [[ "$activation_failed" == "true" ]]; then
      rollback_deployment "$backup_dir" "$previous_state" "$previous_enabled" "$staged_deployment"
      die "New deployment failed to start; previous deployment restored"
    fi
    success "Docker service started on UDP/$PORT."
  fi
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
  validate_repository_policy
  [[ ! -L "$COMPOSE_DIR" ]] || die "Refusing symlinked deployment directory"
  [[ ! -L "$SYSTEMD_UNIT" ]] || die "Refusing symlinked systemd unit"
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
  trap cleanup_install_work EXIT
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
  commit_deployment "$staged_deployment" "$staged_unit" "$work_root"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
