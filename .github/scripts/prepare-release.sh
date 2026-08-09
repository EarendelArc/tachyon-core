#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

die() {
  echo "release preparation failed: $*" >&2
  exit 1
}

if [[ $# -ne 3 ]]; then
  die "usage: $0 <tag> <commit> <release-directory>"
fi

version=$1
commit=${2,,}
release_dir=$3
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
template_dir=$(cd "${script_dir}/../release-notes" && pwd)

[[ "${version}" =~ ^v[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || die "invalid release tag"
[[ "${commit}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "commit must be a full Git object ID"
[[ -d "${release_dir}" ]] || die "release directory does not exist"

platforms=(
  windows_amd64
  windows_arm64
  darwin_amd64
  darwin_arm64
  linux_amd64
  linux_arm64
)

auxiliary_assets=(
  BUILD_METADATA.json
  WINTUN_SIDECAR_CONTRACT.json
  EVIDENCE_MANIFEST.json
  "tachyon-helper-evidence_${version}.tar.gz"
)

zip_names=()
for platform in "${platforms[@]}"; do
  asset="tachyon-core_${version}_${platform}.zip"
  [[ -f "${release_dir}/${asset}" ]] || die "required release asset is missing: ${asset}"
  zip_names+=("${asset}")
done

shopt -s nullglob
actual_zips=("${release_dir}"/*.zip)
[[ ${#actual_zips[@]} -eq ${#zip_names[@]} ]] || \
  die "release directory must contain exactly the six supported ZIP assets"

for asset in "${auxiliary_assets[@]}"; do
  [[ -f "${release_dir}/${asset}" ]] || die "required release metadata asset is missing: ${asset}"
done

expected_files=("${zip_names[@]}" "${auxiliary_assets[@]}")
mapfile -t actual_files < <(find "${release_dir}" -maxdepth 1 -type f \
  ! -name 'RELEASE_NOTES.md' ! -name 'RELEASE_NOTES.zh-CN.md' ! -name 'SHA256SUMS.txt' \
  -printf '%f\n' | LC_ALL=C sort)
mapfile -t expected_sorted < <(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)
[[ "${actual_files[*]}" == "${expected_sorted[*]}" ]] || \
  die "release directory contains an unexpected asset set"

python3 "${script_dir}/validate-release-assets.py" \
  --release-directory "${release_dir}" \
  --version "${version}" \
  --commit "${commit}"

python3 "${script_dir}/prepare-release-metadata.py" \
  --version "${version}" \
  --commit "${commit}" \
  --release-directory "${release_dir}" \
  --template-directory "${template_dir}"

echo "prepared deterministic bilingual release metadata for ${version} at ${commit}"
