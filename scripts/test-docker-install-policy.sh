#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
INSTALLER="$SCRIPT_DIR/install-server-docker.sh"
CONTRACT="$REPO_ROOT/deploy/docker/runtime-contract.json"
DOCKERFILE="$REPO_ROOT/deploy/docker/Dockerfile"

fail() {
  echo "docker install policy test failed: $*" >&2
  exit 1
}

bash -n "$INSTALLER"
# shellcheck disable=SC1090
source "$INSTALLER"

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
5:29.7.2-1~debian.12~bookworm
5:29.7.1-1~debian.12~bookworm
5:28.5.1-1~debian.12~bookworm
VERSIONS
)
[[ "$selected" == '5:29.7.2-1~debian.12~bookworm' ]] \
  || fail "version selection did not choose the newest allowed package"
if select_version_from_list docker-ce <<<'5:30.0.0-1~debian.13~trixie' >/dev/null; then
  fail "unsupported-only package list unexpectedly selected a version"
fi

if grep -Eq 'get\.docker\.com|curl[^|]*\|[[:space:]]*(ba)?sh' "$INSTALLER"; then
  fail "installer contains a remote shell pipeline"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN=python
fi
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3 is required for the JSON fixture test"
"$PYTHON_BIN" - "$CONTRACT" "$DOCKERFILE" "$INSTALLER" <<'PY'
import json
import pathlib
import re
import sys

contract_path, dockerfile_path, installer_path = map(pathlib.Path, sys.argv[1:])
contract = json.loads(contract_path.read_text(encoding="utf-8"))
dockerfile = dockerfile_path.read_text(encoding="utf-8")
installer = installer_path.read_text(encoding="utf-8")

digest = contract["base_image"]["manifest_digest"]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("base image digest is not a full sha256")
reference = f'{contract["base_image"]["repository"]}:{contract["base_image"]["tag"]}@{digest}'
if f"ARG TACHYON_BASE_IMAGE={reference}" not in dockerfile:
    raise SystemExit("checked-in Dockerfile does not default to the contract digest")
if f'TACHYON_BASE_IMAGE="{reference}"' not in installer:
    raise SystemExit("installer does not render the contract digest")
if "https://download.docker.com/linux/$DOCKER_REPO_OS/gpg" not in installer:
    raise SystemExit("installer does not use Docker's official apt key URL")
if "Signed-By: $DOCKER_APT_KEYRING" not in installer:
    raise SystemExit("installer apt source is not bound to its keyring")
if 'DOCKER_APT_PREFERENCES="/etc/apt/preferences.d/tachyon-docker-ce"' not in installer:
    raise SystemExit("installer does not declare a Docker apt preferences policy")
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
PY

echo "docker install policy tests passed"
