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
  COMPOSE_DIR="$fixture/transaction/live"
  SYSTEMD_UNIT="$fixture/transaction/systemd/tachyon-docker.service"
  transaction_work="$fixture/transaction/work"
  staged_transaction="$transaction_work/deployment"
  mkdir -p "$COMPOSE_DIR/config" "$COMPOSE_DIR/logs" "$(dirname "$SYSTEMD_UNIT")" \
    "$staged_transaction/config" "$staged_transaction/logs"
  printf 'old-config\n' > "$COMPOSE_DIR/config/server.json"
  printf 'old-compose\n' > "$COMPOSE_DIR/docker-compose.yaml"
  printf 'old-log\n' > "$COMPOSE_DIR/logs/tachyon-core.log"
  printf 'old-unit\n' > "$SYSTEMD_UNIT"
  printf 'new-config\n' > "$staged_transaction/config/server.json"
  printf 'new-compose\n' > "$staged_transaction/docker-compose.yaml"
  staged_transaction_unit="$transaction_work/tachyon-docker.service"
  printf 'new-unit\n' > "$staged_transaction_unit"
  SYSTEMCTL_RELOADS=0
  systemctl() {
    case "$1" in
      is-active|is-enabled) return 0 ;;
      daemon-reload)
        SYSTEMCTL_RELOADS=$((SYSTEMCTL_RELOADS + 1))
        [[ "$SYSTEMCTL_RELOADS" -gt 1 ]]
        ;;
      *) return 0 ;;
    esac
  }
  if (commit_deployment "$staged_transaction" "$staged_transaction_unit" "$transaction_work" >/dev/null 2>&1); then
    fail "transaction fixture did not inject the activation failure"
  fi
  grep -Fxq 'old-config' "$COMPOSE_DIR/config/server.json" || fail "rollback did not restore the old config"
  grep -Fxq 'old-compose' "$COMPOSE_DIR/docker-compose.yaml" || fail "rollback did not restore the old compose"
  grep -Fxq 'old-log' "$COMPOSE_DIR/logs/tachyon-core.log" || fail "rollback did not restore the old logs"
  grep -Fxq 'old-unit' "$SYSTEMD_UNIT" || fail "rollback did not restore the old systemd unit"
  unset -f systemctl
  COMPOSE_DIR="$old_compose_dir"
  SYSTEMD_UNIT="$old_systemd_unit"
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
