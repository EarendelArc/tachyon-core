#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
INSTALLER="$SCRIPT_DIR/install-server-docker.sh"
CONTRACT="$REPO_ROOT/deploy/docker/runtime-contract.json"
DOCKERFILE="$REPO_ROOT/deploy/docker/Dockerfile"
DOCKERIGNORE="$REPO_ROOT/deploy/docker/.dockerignore"

fail() {
  echo "docker install policy test failed: $*" >&2
  exit 1
}

bash -n "$INSTALLER"
# shellcheck disable=SC1090
source "$INSTALLER"

# Git Bash has no dpkg; production is required to use dpkg's Debian ordering.
dpkg() {
  [[ "$1" == "--compare-versions" && "$3" == "gt" ]] || return 2
  local greatest
  greatest=$(printf '%s\n%s\n' "$2" "$4" | sort -V | tail -1)
  [[ "$greatest" == "$2" && "$2" != "$4" ]]
}

version_allowed docker-ce '5:29.7.2-1~debian.12~bookworm' \
  || fail "supported Docker Engine version rejected"
version_allowed containerd.io '2.2.3-1' \
  || fail "supported containerd version rejected"
version_allowed docker-buildx-plugin '0.34.1-1~debian.13~trixie' \
  || fail "supported buildx version rejected"
version_allowed docker-compose-plugin '5.1.4-1~debian.13~trixie' \
  || fail "supported compose version rejected"

if version_allowed docker-ce '5:30.0.0-1~debian.13~trixie'; then
  fail "future Docker Engine major was accepted"
fi
if version_allowed containerd.io '3.0.0-1'; then
  fail "future containerd major was accepted"
fi

selected=$(select_version_from_list docker-ce <<'VERSIONS'
5:29.7.1-1~debian.12~bookworm
5:28.5.1-1~debian.12~bookworm
5:29.7.2-1~debian.12~bookworm
VERSIONS
)
[[ "$selected" == '5:29.7.2-1~debian.12~bookworm' ]] \
  || fail "dpkg-based version selection did not choose the newest allowed package"
if select_version_from_list docker-ce <<<'5:30.0.0-1~debian.13~trixie' >/dev/null; then
  fail "unsupported-only package list unexpectedly selected a version"
fi

existing_psk='existing-private-psk-0001'
[[ $(select_tgp_psk "$existing_psk" "" 0 false) == "$existing_psk" ]] \
  || fail "idempotent rerun rotated an existing PSK"
[[ $(select_tgp_psk "$existing_psk" "$existing_psk" 0 false) == "$existing_psk" ]] \
  || fail "same explicitly supplied PSK was not preserved"
if (select_tgp_psk "$existing_psk" 'different-private-psk-0002' 0 false >/dev/null 2>&1); then
  fail "implicit PSK replacement was accepted"
fi
if (select_tgp_psk "$existing_psk" 'different-private-psk-0002' 1 false >/dev/null 2>&1); then
  fail "unconfirmed PSK rotation was accepted"
fi
[[ $(select_tgp_psk "$existing_psk" 'different-private-psk-0002' 1 true) == 'different-private-psk-0002' ]] \
  || fail "explicit confirmed PSK rotation failed"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
release_fixture="$fixture/release.json"
if command -v jq >/dev/null 2>&1; then
  TACHYON_VERSION=v1.2.3
  release_commit=0123456789abcdef0123456789abcdef01234567
  cat > "$release_fixture" <<JSON
{
  "tag_name": "v1.2.3",
  "draft": false,
  "prerelease": true,
  "immutable": true,
  "target_commitish": "$release_commit",
  "assets": [
    {"name":"tachyon-core_v1.2.3_linux_amd64.zip","digest":"sha256:$(printf 'a%.0s' {1..64})","size":123,"browser_download_url":"https://github.com/EarendelArc/tachyon-core/releases/download/v1.2.3/core.zip"},
    {"name":"SHA256SUMS.txt","digest":"sha256:$(printf 'b%.0s' {1..64})","size":456,"browser_download_url":"https://github.com/EarendelArc/tachyon-core/releases/download/v1.2.3/SHA256SUMS.txt"}
  ]
}
JSON
  validate_release_metadata "$release_fixture"
  [[ "$RELEASE_COMMIT" == "$release_commit" ]] || fail "release commit was not captured exactly"
  asset_metadata "$release_fixture" 'tachyon-core_v1.2.3_linux_amd64.zip' >/dev/null

  jq '.immutable=false' "$release_fixture" > "$fixture/invalid-release.json"
  if (validate_release_metadata "$fixture/invalid-release.json" >/dev/null 2>&1); then
    fail "mutable release was accepted"
  fi
  jq '.assets += [.assets[0]]' "$release_fixture" > "$fixture/duplicate-assets.json"
  if (asset_metadata "$fixture/duplicate-assets.json" 'tachyon-core_v1.2.3_linux_amd64.zip' >/dev/null 2>&1); then
    fail "duplicate exact asset name was accepted"
  fi
  cat > "$fixture/tag-ref.json" <<JSON
{"object":{"type":"tag","sha":"$(printf 'c%.0s' {1..40})"}}
JSON
  cat > "$fixture/tag-object.json" <<JSON
{"object":{"type":"commit","sha":"$release_commit"}}
JSON
  validate_annotated_tag_metadata "$fixture/tag-ref.json" "$fixture/tag-object.json" "$release_commit"
  jq '.object.type="commit"' "$fixture/tag-ref.json" > "$fixture/lightweight-ref.json"
  if (validate_annotated_tag_metadata "$fixture/lightweight-ref.json" "$fixture/tag-object.json" "$release_commit" >/dev/null 2>&1); then
    fail "lightweight release tag was accepted"
  fi
else
  [[ "${CI:-false}" != "true" ]] || fail "jq is required for release metadata fixtures in CI"
  echo "release metadata shell fixtures skipped: jq unavailable" >&2
fi

original_repo="$GITHUB_REPO"
GITHUB_REPO=example/untrusted
TACHYON_DEV_MODE=0

for override in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH; do
  if (export "$override=attacker-controlled"; reject_docker_client_overrides >/dev/null 2>&1); then
    fail "$override was accepted"
  fi
done
grep -Fq 'unix:///var/run/docker.sock' "$INSTALLER" \
  || fail "installer does not pin the local system Docker socket"
grep -Fq 'docker context show' "$INSTALLER" \
  || fail "installer does not inspect the active Docker context"
if (validate_repository_policy >/dev/null 2>&1); then
  fail "custom repository was accepted in formal mode"
fi
TACHYON_DEV_MODE=1
validate_repository_policy >/dev/null 2>&1
GITHUB_REPO="$original_repo"
TACHYON_DEV_MODE=0

if grep -Eq 'get\.docker\.com|curl[^|]*\|[[:space:]]*(ba)?sh' "$INSTALLER"; then
  fail "installer contains a remote shell pipeline"
fi
grep -Fq 'dpkg --compare-versions' "$INSTALLER" \
  || fail "installer does not use dpkg version ordering"
grep -Fq "$DOCKER_APT_KEY_FINGERPRINT" "$INSTALLER" \
  || fail "installer does not pin the official Docker apt key fingerprint"

deployment="$fixture/deployment"
context="$fixture/context"
mkdir -p "$deployment/bin" "$deployment/config" "$deployment/logs" "$deployment/evidence"
printf '#!/bin/sh\n' > "$deployment/bin/tachyon-core"
printf 'TACHYON_PSK=decoy-super-secret\n' > "$deployment/config/server.json"
printf 'decoy log secret\n' > "$deployment/logs/tachyon-core.log"
printf 'decoy release evidence\n' > "$deployment/evidence/release.json"
printf 'decoy host file\n' > "$deployment/system-file"
prepare_build_context "$deployment/bin/tachyon-core" "$context"

manifest=$(cd "$context" && find . -mindepth 1 -type f -printf '%P\n' | LC_ALL=C sort)
expected_manifest=$'.dockerignore\nDockerfile\nbin/tachyon-core'
[[ "$manifest" == "$expected_manifest" ]] \
  || fail "minimal context manifest mismatch: $manifest"
if grep -R -Fq 'decoy-super-secret' "$context" || grep -R -Fq 'decoy log secret' "$context" || grep -R -Fq 'decoy release evidence' "$context"; then
  fail "PSK, config, log, or release evidence entered the Docker build context"
fi
cmp "$context/.dockerignore" "$DOCKERIGNORE" \
  || fail "generated .dockerignore differs from the checked-in contract"

old_compose_dir="$COMPOSE_DIR"
COMPOSE_DIR="$fixture/live"
mkdir -p "$deployment/config" "$deployment/logs"
write_compose "$deployment" 'tachyon-core-local:0123456789ab'
compose="$deployment/docker-compose.yaml"
grep -Fq 'image: tachyon-core-local:0123456789ab' "$compose" || fail "compose image is not commit-pinned"
grep -Fq 'network_mode: host' "$compose" || fail "compose lost host networking"
grep -Fq 'user: "65532:65532"' "$compose" || fail "compose lost UID 65532"
grep -Fq -- '- NET_BIND_SERVICE' "$compose" || fail "compose lost CAP_NET_BIND_SERVICE"
grep -Fq "$COMPOSE_DIR/config/server.json:/etc/tachyon/server.json:ro" "$compose" || fail "config is not mounted read-only"
grep -Fq "$COMPOSE_DIR/logs:/var/log/tachyon:rw" "$compose" || fail "logs are not mounted writable"
COMPOSE_DIR="$old_compose_dir"

if [[ "$(uname -s)" == "Linux" ]]; then
  old_systemd_unit="$SYSTEMD_UNIT"
  old_transaction_dir="$TRANSACTION_DIR"
  old_health_timeout="$DEPLOYMENT_HEALTH_TIMEOUT_SECONDS"
  INSTALL_WORK_ROOT=""
  old_proc_root="$PROC_ROOT"
  PROC_ROOT="$fixture/proc"
  fake_pid=4242
  mkdir -p "$PROC_ROOT/$fake_pid/fd" "$PROC_ROOT/$fake_pid/net"
  cat > "$PROC_ROOT/$fake_pid/net/udp" <<'UDP'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000 65532 0 987654 2 0000000000000000 0
UDP
  : > "$PROC_ROOT/$fake_pid/net/udp6"
  ln -s 'socket:[987654]' "$PROC_ROOT/$fake_pid/fd/7"
  container_owns_udp_listener "$fake_pid" 443 \
    || fail "owned UDP listener fixture was not recognized"
  if container_owns_udp_listener "$fake_pid" 444; then
    fail "wrong UDP port was recognized as owned"
  fi
  COMPOSE_DIR="$fixture/runtime-gate"
  mkdir -p "$COMPOSE_DIR"
  : > "$COMPOSE_DIR/docker-compose.yaml"
  runtime_container_id=$(printf 'a%.0s' {1..64})
  runtime_image_id="sha256:$(printf 'b%.0s' {1..64})"
  docker() {
    if [[ "$1" == "compose" ]]; then
      printf '%s\n' "$runtime_container_id"
      return 0
    fi
    if [[ "$1 $2" == "image inspect" ]]; then
      printf '%s\n' "$runtime_image_id"
      return 0
    fi
    if [[ "$1" == "inspect" ]]; then
      case "$3" in
        '{{.Id}}') printf '%s\n' "$runtime_container_id" ;;
        '{{.State.Status}}') printf 'running\n' ;;
        '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}') printf 'healthy\n' ;;
        '{{.Config.Image}}') printf 'tachyon-core-local:0123456789ab\n' ;;
        '{{.Image}}') printf '%s\n' "$runtime_image_id" ;;
        '{{index .Config.Labels "com.docker.compose.service"}}') printf 'tachyon-core\n' ;;
        '{{.State.Pid}}') printf '%s\n' "$fake_pid" ;;
        *) return 2 ;;
      esac
      return 0
    fi
    return 2
  }
  verify_running_deployment 'tachyon-core-local:0123456789ab' 443 >/dev/null \
    || fail "healthy/image/UDP runtime gate rejected a valid fixture"
  unset -f docker
  PROC_ROOT="$old_proc_root"

  SERVICE_ACTIVE=true
  SERVICE_ENABLED=true
  FAIL_DAEMON_RELOAD=false
  VERIFY_DEPLOYMENT=true
  systemctl() {
    case "$1" in
      is-active) [[ "$SERVICE_ACTIVE" == "true" ]] ;;
      is-enabled) [[ "$SERVICE_ENABLED" == "true" ]] ;;
      start) SERVICE_ACTIVE=true ;;
      stop) SERVICE_ACTIVE=false ;;
      enable)
        SERVICE_ENABLED=true
        [[ " $* " != *" --now "* ]] || SERVICE_ACTIVE=true
        ;;
      disable)
        SERVICE_ENABLED=false
        [[ " $* " != *" --now "* ]] || SERVICE_ACTIVE=false
        ;;
      daemon-reload) [[ "$FAIL_DAEMON_RELOAD" != "true" ]] ;;
      *) return 2 ;;
    esac
  }
  verify_running_deployment() { [[ "$VERIFY_DEPLOYMENT" == "true" ]]; }

  prepare_transaction_fixture() {
    local root="$1"
    rm -rf "$root"
    COMPOSE_DIR="$root/live"
    SYSTEMD_UNIT="$root/systemd/tachyon-docker.service"
    TRANSACTION_DIR="$root/.tachyon-docker.transaction"
    mkdir -p "$COMPOSE_DIR/config" "$COMPOSE_DIR/logs" "$(dirname "$SYSTEMD_UNIT")" \
      "$root/staged/config" "$root/staged/logs"
    printf '{"tgp":{"auth":{"psk":"old-private-psk-0001"}}}\n' > "$COMPOSE_DIR/config/server.json"
    printf 'old-compose\n' > "$COMPOSE_DIR/docker-compose.yaml"
    printf 'old-log\n' > "$COMPOSE_DIR/logs/tachyon-core.log"
    printf 'old-unit\n' > "$SYSTEMD_UNIT"
    printf '{"tgp":{"auth":{"psk":"new-private-psk-0002"}}}\n' > "$root/staged/config/server.json"
    printf 'new-compose\n' > "$root/staged/docker-compose.yaml"
    printf 'new-unit\n' > "$root/staged-unit"
  }

  assert_old_transaction_restored() {
    grep -Fq 'old-private-psk-0001' "$COMPOSE_DIR/config/server.json" || fail "rollback did not restore the old PSK"
    grep -Fxq 'old-compose' "$COMPOSE_DIR/docker-compose.yaml" || fail "rollback did not restore old compose"
    grep -Fxq 'old-log' "$COMPOSE_DIR/logs/tachyon-core.log" || fail "rollback did not restore old logs"
    grep -Fxq 'old-unit' "$SYSTEMD_UNIT" || fail "rollback did not restore old unit"
    [[ ! -e "$TRANSACTION_DIR" ]] || fail "successful rollback retained its journal"
  }

  transaction_root="$fixture/transaction-failure"
  prepare_transaction_fixture "$transaction_root"
  VERIFY_DEPLOYMENT=false
  if (
    trap on_installer_exit EXIT
    trap 'on_installer_signal INT 130' INT
    trap 'on_installer_signal TERM 143' TERM
    trap 'on_installer_signal HUP 129' HUP
    commit_deployment "$transaction_root/staged" "$transaction_root/staged-unit" 'tachyon-core-local:0123456789ab' 443
  ) >/dev/null 2>&1; then
    fail "unhealthy deployment fixture unexpectedly committed"
  fi
  assert_old_transaction_restored

  for signal_case in 'INT 130' 'TERM 143' 'HUP 129'; do
    read -r signal_name expected_status <<< "$signal_case"
    transaction_root="$fixture/transaction-signal-$signal_name"
    prepare_transaction_fixture "$transaction_root"
    initialize_transaction_journal active enabled
    ACTIVE_TRANSACTION=true
    write_transaction_field phase switching
    mv "$COMPOSE_DIR" "$TRANSACTION_DIR/backup/deployment"
    write_transaction_field phase old-backed-up
    mv "$transaction_root/staged" "$COMPOSE_DIR"
    write_transaction_field phase deployment-active
    set +e
    (
      trap on_installer_exit EXIT
      ACTIVE_TRANSACTION=true
      on_installer_signal "$signal_name" "$expected_status"
    ) >/dev/null 2>&1
    signal_status=$?
    set -e
    [[ "$signal_status" -eq "$expected_status" ]] \
      || fail "$signal_name fixture returned $signal_status instead of $expected_status"
    assert_old_transaction_restored
  done

  transaction_root="$fixture/transaction-sigkill-recovery"
  prepare_transaction_fixture "$transaction_root"
  initialize_transaction_journal active enabled
  write_transaction_field phase switching
  mv "$COMPOSE_DIR" "$TRANSACTION_DIR/backup/deployment"
  write_transaction_field phase old-backed-up
  mv "$transaction_root/staged" "$COMPOSE_DIR"
  write_transaction_field phase deployment-active
  ACTIVE_TRANSACTION=false
  recover_pending_transaction >/dev/null
  assert_old_transaction_restored

  transaction_root="$fixture/transaction-committed-cleanup"
  prepare_transaction_fixture "$transaction_root"
  initialize_transaction_journal active enabled
  mv "$COMPOSE_DIR" "$TRANSACTION_DIR/backup/deployment"
  mv "$transaction_root/staged" "$COMPOSE_DIR"
  write_transaction_field phase committed
  recover_pending_transaction >/dev/null
  grep -Fxq 'new-compose' "$COMPOSE_DIR/docker-compose.yaml" || fail "committed recovery rolled back the new deployment"
  [[ ! -e "$TRANSACTION_DIR" ]] || fail "committed recovery retained its journal"

  transaction_root="$fixture/transaction-success"
  prepare_transaction_fixture "$transaction_root"
  VERIFY_DEPLOYMENT=true
  SERVICE_ACTIVE=true
  SERVICE_ENABLED=false
  (
    trap on_installer_exit EXIT
    commit_deployment "$transaction_root/staged" "$transaction_root/staged-unit" 'tachyon-core-local:0123456789ab' 443
  ) >/dev/null
  grep -Fxq 'new-compose' "$COMPOSE_DIR/docker-compose.yaml" || fail "successful transaction did not activate new compose"
  [[ ! -e "$TRANSACTION_DIR" ]] || fail "successful transaction retained its journal"

  unset -f systemctl
  unset -f verify_running_deployment
  unset -f prepare_transaction_fixture
  unset -f assert_old_transaction_restored
  COMPOSE_DIR="$old_compose_dir"
  SYSTEMD_UNIT="$old_systemd_unit"
  TRANSACTION_DIR="$old_transaction_dir"
  DEPLOYMENT_HEALTH_TIMEOUT_SECONDS="$old_health_timeout"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN=python
fi
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3 is required for the JSON fixture test"
"$PYTHON_BIN" - "$CONTRACT" "$DOCKERFILE" "$DOCKERIGNORE" "$INSTALLER" "$REPO_ROOT/.github/scripts/validate-published-release.py" <<'PY'
import json
import pathlib
import re
import sys

contract_path, dockerfile_path, dockerignore_path, installer_path, validator_path = map(pathlib.Path, sys.argv[1:])
contract = json.loads(contract_path.read_text(encoding="utf-8"))
dockerfile = dockerfile_path.read_text(encoding="utf-8")
dockerignore = dockerignore_path.read_text(encoding="utf-8")
installer = installer_path.read_text(encoding="utf-8")
published_validator = validator_path.read_text(encoding="utf-8")

if contract["schema_version"] != 3:
    raise SystemExit("Docker runtime contract schema version changed")

digest = contract["base_image"]["manifest_digest"]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("base image digest is not a full sha256")
reference = f'{contract["base_image"]["repository"]}:{contract["base_image"]["tag"]}@{digest}'
if f"ARG TACHYON_BASE_IMAGE={reference}" not in dockerfile:
    raise SystemExit("checked-in Dockerfile does not default to the contract digest")
if f'TACHYON_BASE_IMAGE="{reference}"' not in installer:
    raise SystemExit("installer does not render the contract digest")
if dockerignore != "**\n!Dockerfile\n!.dockerignore\n!bin/\n!bin/tachyon-core\n":
    raise SystemExit("Docker context allowlist changed")
if "https://download.docker.com/linux/$DOCKER_REPO_OS/gpg" not in installer:
    raise SystemExit("installer does not use Docker's official apt key URL")
if "Signed-By: $DOCKER_APT_KEYRING" not in installer:
    raise SystemExit("installer apt source is not bound to its keyring")
if 'Pin-Priority: -1' not in installer:
    raise SystemExit("installer does not reject package versions outside the allowed majors")

expected = {
    "docker-ce": 29,
    "docker-ce-cli": 29,
    "containerd.io": 2,
    "docker-buildx-plugin": 0,
    "docker-compose-plugin": 5,
}
if contract["package_major_policy"] != expected:
    raise SystemExit("package major policy changed without updating the test contract")
if contract["apt"]["key_fingerprint"] != "9DC858229FC7DD38854AE2D88D81803C0EBFCD88":
    raise SystemExit("Docker apt fingerprint contract changed")
if contract["build_context"]["files"] != [".dockerignore", "Dockerfile", "bin/tachyon-core"]:
    raise SystemExit("minimal Docker context contract changed")
if contract["daemon"] != {
    "context": "default",
    "endpoint": "unix:///var/run/docker.sock",
    "remote_overrides_forbidden": True,
}:
    raise SystemExit("local Docker daemon contract changed")
if contract["transaction"] != {
    "journal": "/opt/.tachyon-docker.transaction",
    "lock": "/run/tachyon/docker-installer.lock",
    "lock_mechanism": "nonblocking-flock-process-lifetime",
    "owner_pid_is_diagnostic_only": True,
    "signals": ["INT", "TERM", "HUP"],
    "recover_on_next_run": True,
}:
    raise SystemExit("persistent Docker transaction contract changed")
if contract["activation_gates"] != [
    "compose-container-identity",
    "exact-image-id",
    "healthy",
    "core-owned-udp-listener",
]:
    raise SystemExit("Docker activation gate contract changed")
if contract["container"] != {
    "uid": 65532,
    "gid": 65532,
    "network_mode": "host",
    "capabilities": ["NET_BIND_SERVICE"],
    "config_read_only": True,
    "logs_writable": True,
}:
    raise SystemExit("static container runtime contract changed")
if contract["release_policy"] != {
    "repository": "EarendelArc/tachyon-core",
    "draft": False,
    "prerelease": True,
    "immutable": True,
    "annotated_tag_required": True,
    "asset_digest_and_size_required": True,
}:
    raise SystemExit("release installation contract changed")

for field in ("tag_name", "prerelease", "immutable", "target_commitish", "digest", "size"):
    if field not in installer:
        raise SystemExit(f"installer release verification omits {field}")
    if field not in published_validator:
        raise SystemExit(f"post-release validator contract omits {field}")
for required in (
    ".tachyon-docker.transaction",
    "flock -n",
    "owner_pid=",
    "on_installer_signal INT 130",
    "on_installer_signal TERM 143",
    "on_installer_signal HUP 129",
    "recover_pending_transaction",
    "docker context show",
    "unix:///var/run/docker.sock",
    "container_owns_udp_listener",
    "{{.State.Health.Status}}",
    "{{.Config.Image}}",
    "{{.Image}}",
):
    if required not in installer:
        raise SystemExit(f"installer runtime policy omits {required}")
if ".object.type == \"tag\"" not in installer or "Annotated release tag" not in installer:
    raise SystemExit("installer does not require an annotated release tag")
if "contains(" in installer or ".[0].tag_name" in installer:
    raise SystemExit("installer uses ambiguous release or asset selection")
if 'GITHUB_REPO="${TACHYON_CORE_REPO:-$OFFICIAL_GITHUB_REPO}"' not in installer:
    raise SystemExit("official repository default is missing")
if 'TACHYON_DEV_MODE' not in installer:
    raise SystemExit("custom repository is not development-gated")
PY

echo "docker install policy tests passed"
