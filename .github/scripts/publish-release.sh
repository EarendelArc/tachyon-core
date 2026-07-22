#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

die() {
  echo "release publication failed: $*" >&2
  exit 1
}

if [[ $# -ne 4 ]]; then
  die "usage: $0 <tag> <commit> <prerelease> <release-directory>"
fi

version=$1
commit=$2
prerelease=$3
release_dir=$4
repository=${GITHUB_REPOSITORY:-}

[[ "${version}" =~ ^v[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || die "invalid release tag"
[[ "${commit}" =~ ^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$ ]] || die "commit must be a full Git object ID"
[[ "${prerelease}" == "true" || "${prerelease}" == "false" ]] || die "prerelease must be true or false"
[[ "${repository}" == */* ]] || die "GITHUB_REPOSITORY must identify owner/repository"
[[ -f "${release_dir}/RELEASE_NOTES.md" ]] || die "English release notes are missing"
[[ -f "${release_dir}/RELEASE_NOTES.zh-CN.md" ]] || die "Simplified Chinese release notes are missing"
[[ -f "${release_dir}/SHA256SUMS.txt" ]] || die "checksum file is missing"

shopt -s nullglob
zip_assets=("${release_dir}"/*.zip)
[[ ${#zip_assets[@]} -gt 0 ]] || die "release ZIP assets are missing"
assets=(
  "${zip_assets[@]}"
  "${release_dir}/RELEASE_NOTES.md"
  "${release_dir}/RELEASE_NOTES.zh-CN.md"
  "${release_dir}/SHA256SUMS.txt"
)

expected_checksum_entries=(RELEASE_NOTES.md RELEASE_NOTES.zh-CN.md)
for asset in "${zip_assets[@]}"; do
  expected_checksum_entries+=("$(basename "${asset}")")
done

for entry in "${expected_checksum_entries[@]}"; do
  [[ $(grep -Ec "^[0-9a-f]{64}  ${entry//./\\.}$" "${release_dir}/SHA256SUMS.txt") -eq 1 ]] || \
    die "checksum manifest must contain exactly one entry for ${entry}"
done
[[ $(wc -l < "${release_dir}/SHA256SUMS.txt") -eq ${#expected_checksum_entries[@]} ]] || \
  die "checksum manifest contains an unexpected asset set"
(
  cd "${release_dir}"
  sha256sum --check --strict SHA256SUMS.txt
) || die "release asset checksum verification failed"

body_file=$(mktemp)
{
  cat "${release_dir}/RELEASE_NOTES.md"
  printf '\n\n---\n\n'
  cat "${release_dir}/RELEASE_NOTES.zh-CN.md"
} > "${body_file}"

# Only a definite not-found result permits creation. Authentication, transport,
# and API failures must not be mistaken for release absence.
set +e
existing_output=$(gh release view "${version}" --json isDraft,url 2>&1)
existing_status=$?
set -e
if [[ ${existing_status} -eq 0 ]]; then
  die "release ${version} already exists; refusing to edit or replace it: ${existing_output}"
fi
if [[ "${existing_output}" != *"release not found"* && "${existing_output}" != *"HTTP 404"* ]]; then
  die "could not prove that release ${version} is absent: ${existing_output}"
fi

draft_created=false
draft_id=""

cleanup_draft() {
  local status=$?
  trap - EXIT

  rm -f "${body_file}"

  if [[ ${status} -ne 0 && "${draft_created}" == "true" ]]; then
    if [[ -z "${draft_id}" ]]; then
      draft_id=$(gh release view "${version}" --json databaseId,isDraft --jq 'select(.isDraft == true) | .databaseId' 2>/dev/null || true)
    fi

    if [[ -z "${draft_id}" ]]; then
      echo "::warning::Publication failed after draft creation, but the draft ID could not be recovered. Inspect ${version} manually; no existing release was overwritten."
    else
      local is_draft
      is_draft=$(gh api "repos/${repository}/releases/${draft_id}" --jq '.draft' 2>/dev/null || true)
      if [[ "${is_draft}" == "true" ]]; then
        if gh api --method DELETE "repos/${repository}/releases/${draft_id}" --silent; then
          echo "::warning::Publication failed; deleted incomplete draft release ${version}."
        else
          echo "::warning::Publication failed and incomplete draft ${version} could not be deleted. Remove draft ID ${draft_id} manually."
        fi
      else
        echo "::error::Publication failed, but release ${version} is no longer a draft. Refusing destructive cleanup."
      fi
    fi
  fi

  exit "${status}"
}
trap cleanup_draft EXIT

prerelease_flag=()
if [[ "${prerelease}" == "true" ]]; then
  prerelease_flag=(--prerelease)
fi

gh release create "${version}" \
  --draft \
  --verify-tag \
  --target "${commit}" \
  --title "Tachyon Core ${version}" \
  --notes-file "${body_file}" \
  "${prerelease_flag[@]}"
draft_created=true

draft_id=$(gh release view "${version}" --json databaseId,isDraft --jq 'select(.isDraft == true) | .databaseId')
[[ -n "${draft_id}" ]] || die "created release is not an identifiable draft"

# Upload the complete asset set exactly once while the release is still mutable.
gh release upload "${version}" "${assets[@]}"

# Publish only the draft created above. Immutable-release protection, when enabled,
# takes effect after this transition with the complete asset set already present.
gh api --method PATCH "repos/${repository}/releases/${draft_id}" -F draft=false --silent
draft_id=""

echo "published release ${version} from commit ${commit}"
