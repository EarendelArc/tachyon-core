#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

die() {
  echo "published release verification failed: $*" >&2
  exit 1
}

if [[ $# -ne 3 ]]; then
  die "usage: $0 <tag> <commit> <release-directory>"
fi

version=$1
commit=${2,,}
release_dir=$3
repository=${GITHUB_REPOSITORY:-}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

[[ "${repository}" == */* ]] || die "GITHUB_REPOSITORY must identify owner/repository"
[[ -d "${release_dir}" ]] || die "release directory does not exist"

release_json=$(mktemp)
cleanup() {
  rm -f "${release_json}"
}
trap cleanup EXIT

gh api "repos/${repository}/releases/tags/${version}" > "${release_json}" || \
  die "could not read published release"
python3 "${script_dir}/validate-published-release.py" \
  --release-json "${release_json}" \
  --version "${version}" \
  --commit "${commit}" \
  --release-directory "${release_dir}"
