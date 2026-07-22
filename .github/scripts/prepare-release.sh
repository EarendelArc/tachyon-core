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

render_template() {
  local template=$1
  local output=$2

  sed \
    -e "s/{{VERSION}}/${version}/g" \
    -e "s/{{COMMIT}}/${commit}/g" \
    "${template}" > "${output}"
  if grep -Eq '{{(VERSION|COMMIT)}}' "${output}"; then
    die "release note template contains an unresolved placeholder: $(basename "${template}")"
  fi
}

render_template "${template_dir}/RELEASE_NOTES.md.tmpl" "${release_dir}/RELEASE_NOTES.md"
render_template "${template_dir}/RELEASE_NOTES.zh-CN.md.tmpl" "${release_dir}/RELEASE_NOTES.zh-CN.md"

checksum_inputs=(RELEASE_NOTES.md RELEASE_NOTES.zh-CN.md "${zip_names[@]}")
(
  cd "${release_dir}"
  sha256sum --text "${checksum_inputs[@]}" > SHA256SUMS.txt
)

echo "prepared deterministic bilingual release metadata for ${version} at ${commit}"
