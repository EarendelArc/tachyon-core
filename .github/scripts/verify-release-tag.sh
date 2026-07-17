#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

readonly FETCH_REF="refs/tachyon-release/verified-tag"

die() {
  echo "release tag verification failed: $*" >&2
  exit 1
}

if [[ $# -lt 2 || $# -gt 4 ]]; then
  die "usage: $0 <tag> <expected-commit> [remote] [expected-tag-object]"
fi

release_tag=$1
expected_commit=$2
remote=${3:-origin}
expected_tag_object=${4:-}

if [[ ! "${release_tag}" =~ ^v[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
  die "tag must start with v and contain only letters, numbers, '.', '_' or '-'"
fi
git check-ref-format "refs/tags/${release_tag}" >/dev/null || die "invalid tag ref: ${release_tag}"

if [[ ! "${expected_commit}" =~ ^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$ ]]; then
  die "expected commit must be a full Git object ID"
fi
expected_commit=$(git rev-parse --verify "${expected_commit}^{commit}") || die "expected commit is not available"

# Fetch only the requested remote tag into an isolated ref. This avoids trusting
# a same-named local tag left by checkout or by a previous fetch.
git update-ref -d "${FETCH_REF}" >/dev/null 2>&1 || true
git fetch --quiet --no-tags "${remote}" "refs/tags/${release_tag}:${FETCH_REF}" || \
  die "tag ${release_tag} does not exist on remote ${remote}"

tag_object=$(git rev-parse --verify "${FETCH_REF}") || die "fetched tag object is unavailable"
tag_type=$(git cat-file -t "${tag_object}") || die "cannot inspect fetched tag object"
tag_commit=$(git rev-parse --verify "${FETCH_REF}^{commit}") || die "tag does not peel to a commit"

if [[ -n "${expected_tag_object}" ]]; then
  if [[ ! "${expected_tag_object}" =~ ^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$ ]]; then
    die "expected tag object must be a full Git object ID"
  fi
  if [[ "${tag_object}" != "${expected_tag_object}" ]]; then
    die "tag ${release_tag} object changed from ${expected_tag_object} to ${tag_object}"
  fi
fi

if [[ "${tag_commit}" != "${expected_commit}" ]]; then
  die "tag ${release_tag} points to ${tag_commit}, expected ${expected_commit}"
fi

verification=""
verify_output=""
if verify_output=$(git verify-tag "${FETCH_REF}" 2>&1); then
  verification="signature"
  [[ -z "${verify_output}" ]] || printf '%s\n' "${verify_output}"
  echo "release tag ${release_tag}: cryptographic signature verified with git verify-tag"
else
  if [[ "${tag_type}" == "commit" ]]; then
    verification="ref-commit"
  elif [[ "${tag_type}" == "tag" && "${verify_output}" == *"no signature found"* ]]; then
    verification="ref-commit"
  else
    printf '%s\n' "${verify_output}" >&2
    die "tag contains a signature that git verify-tag could not validate"
  fi

  echo "::warning::Tag ${release_tag} is unsigned; signature authenticity is unavailable. The exact remote tag ref and expected commit equality were verified."
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "tag=${release_tag}"
    echo "commit=${tag_commit}"
    echo "tag_object=${tag_object}"
    echo "verification=${verification}"
  } >> "${GITHUB_OUTPUT}"
fi

echo "release tag verified: tag=${release_tag} commit=${tag_commit} method=${verification}"
