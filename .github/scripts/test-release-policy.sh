#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
verify_script="${repo_root}/.github/scripts/verify-release-tag.sh"
publish_script="${repo_root}/.github/scripts/publish-release.sh"
workflow="${repo_root}/.github/workflows/release.yml"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
  echo "release policy test failed: $*" >&2
  exit 1
}

expect_failure() {
  local name=$1
  local expected=$2
  shift 2

  local output
  local status
  set +e
  output=$("$@" 2>&1)
  status=$?
  set -e

  [[ ${status} -ne 0 ]] || fail "${name} unexpectedly succeeded"
  grep -Fq "${expected}" <<<"${output}" || fail "${name} did not report '${expected}': ${output}"
}

run_gate() {
  local checkout=$1
  local tag=$2
  local commit=$3
  local output_file=${4:-}

  if [[ -n "${output_file}" ]]; then
    (cd "${checkout}" && GITHUB_OUTPUT="${output_file}" bash "${verify_script}" "${tag}" "${commit}" origin)
  else
    (cd "${checkout}" && bash "${verify_script}" "${tag}" "${commit}" origin)
  fi
}

remote="${tmp_dir}/remote.git"
source_repo="${tmp_dir}/source"
checkout="${tmp_dir}/checkout"

git init --quiet --bare --initial-branch=main "${remote}"
git init --quiet --initial-branch=main "${source_repo}"
git -C "${source_repo}" config user.name "Release Policy Test"
git -C "${source_repo}" config user.email "release-policy@example.invalid"
git -C "${source_repo}" config core.autocrlf false

printf 'first\n' > "${source_repo}/payload.txt"
git -C "${source_repo}" add payload.txt
git -C "${source_repo}" commit --quiet -m "first"
first_commit=$(git -C "${source_repo}" rev-parse HEAD)
git -C "${source_repo}" tag v1.2.3 "${first_commit}"

printf 'second\n' > "${source_repo}/payload.txt"
git -C "${source_repo}" commit --quiet -am "second"
second_commit=$(git -C "${source_repo}" rev-parse HEAD)
git -C "${source_repo}" tag --annotate v1.2.4 --message "unsigned release tag" "${second_commit}"
git -C "${source_repo}" remote add origin "${remote}"
git -C "${source_repo}" push --quiet origin HEAD:refs/heads/main refs/tags/v1.2.3 refs/tags/v1.2.4

git clone --quiet "${remote}" "${checkout}"
git -C "${checkout}" checkout --quiet --detach "${second_commit}"

expect_failure \
  "wrong tag" \
  "does not exist on remote" \
  run_gate "${checkout}" v9.9.9 "${second_commit}"

expect_failure \
  "tag/commit mismatch" \
  "points to ${first_commit}, expected ${second_commit}" \
  run_gate "${checkout}" v1.2.3 "${second_commit}"

output_file="${tmp_dir}/github-output"
run_gate "${checkout}" v1.2.4 "${second_commit}" "${output_file}"
grep -Fqx "tag=v1.2.4" "${output_file}" || fail "correct tag output is missing"
grep -Fqx "commit=${second_commit}" "${output_file}" || fail "correct commit output is missing"
grep -Fqx "verification=ref-commit" "${output_file}" || fail "unsigned fallback was not explicit"

fake_bin="${tmp_dir}/fake-bin"
fake_state="${tmp_dir}/fake-gh-state"
fake_log="${tmp_dir}/fake-gh-log"
release_assets="${tmp_dir}/release-assets"
mkdir -p "${fake_bin}" "${release_assets}"
printf 'asset\n' > "${release_assets}/tachyon-core_v1.2.4_linux_amd64.zip"
printf 'checksum\n' > "${release_assets}/SHA256SUMS.txt"
printf 'notes\n' > "${release_assets}/RELEASE_NOTES.md"

cat > "${fake_bin}/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${FAKE_GH_LOG}"

if [[ "$1 $2" == "release view" ]]; then
  if [[ "${FAKE_GH_MODE}" == "existing" ]]; then
    echo '{"isDraft":false,"url":"https://example.invalid/release"}'
    exit 0
  fi
  if [[ -f "${FAKE_GH_STATE}" ]]; then
    echo '123'
    exit 0
  fi
  echo 'release not found' >&2
  exit 1
fi

if [[ "$1 $2" == "release create" ]]; then
  printf 'draft\n' > "${FAKE_GH_STATE}"
  exit 0
fi

if [[ "$1 $2" == "release upload" ]]; then
  if [[ "${FAKE_GH_MODE}" == "upload-fail" ]]; then
    echo 'simulated upload failure' >&2
    exit 42
  fi
  exit 0
fi

if [[ "$1" == "api" ]]; then
  if [[ " $* " == *" --method DELETE "* ]]; then
    rm -f "${FAKE_GH_STATE}"
    exit 0
  fi
  if [[ " $* " == *" --method PATCH "* ]]; then
    exit 0
  fi
  echo 'true'
  exit 0
fi

echo "unexpected fake gh command: $*" >&2
exit 2
FAKE_GH
chmod +x "${fake_bin}/gh"

run_publish() {
  local mode=$1
  PATH="${fake_bin}:${PATH}" \
    FAKE_GH_MODE="${mode}" \
    FAKE_GH_STATE="${fake_state}" \
    FAKE_GH_LOG="${fake_log}" \
    GITHUB_REPOSITORY="tachyon-space/tachyon-core" \
    bash "${publish_script}" v1.2.4 "${second_commit}" true "${release_assets}"
}

rm -f "${fake_state}" "${fake_log}"
expect_failure "existing release" "already exists; refusing to edit or replace" run_publish existing
! grep -Eq '^release (create|upload)' "${fake_log}" || fail "existing release path performed a write"

rm -f "${fake_state}" "${fake_log}"
run_publish happy
grep -Fq 'release create v1.2.4 --draft --verify-tag' "${fake_log}" || fail "release was not created as a verified draft"
[[ $(grep -Fc 'release upload v1.2.4' "${fake_log}") -eq 1 ]] || fail "assets were not uploaded exactly once"
grep -Fq 'api --method PATCH repos/tachyon-space/tachyon-core/releases/123' "${fake_log}" || fail "draft was not published through its release ID"

rm -f "${fake_state}" "${fake_log}"
expect_failure "asset upload" "simulated upload failure" run_publish upload-fail
grep -Fq 'api --method DELETE repos/tachyon-space/tachyon-core/releases/123' "${fake_log}" || fail "failed upload did not clean up its draft"
[[ ! -f "${fake_state}" ]] || fail "failed upload left the fake draft behind"

checkout_count=$(grep -Fc 'ref: ${{ needs.verify_tag.outputs.commit }}' "${workflow}")
[[ ${checkout_count} -ge 4 ]] || fail "release jobs are not all pinned to the verified commit"
gate_count=$(grep -Fc 'bash .github/scripts/verify-release-tag.sh' "${workflow}")
[[ ${gate_count} -ge 2 ]] || fail "initial and pre-publish tag gates are both required"
grep -Fq -- '--target "${commit}"' "${publish_script}" || fail "release target is not pinned to the verified commit"
grep -Fq -- '--verify-tag' "${publish_script}" || fail "release creation does not require an existing tag"
grep -Fq 'EXPECTED_TAG_OBJECT: ${{ needs.verify_tag.outputs.tag_object }}' "${workflow}" || fail "pre-publish gate does not pin the tag object"
grep -Fq 'group: release-${{ github.repository }}-${{ github.event_name' "${workflow}" || fail "release concurrency is not grouped by tag"
grep -Fq 'cancel-in-progress: false' "${workflow}" || fail "same-tag release runs must serialize instead of cancelling"
grep -Fq 'source_date_epoch=$(git show -s --format=%ct "${VERIFIED_COMMIT}")' "${workflow}" || fail "build metadata does not use verified commit time"
grep -Fq 'zip -X -9' "${workflow}" || fail "release ZIP metadata is not normalized"
if grep -Fq 'date -u +%Y-%m-%dT%H:%M:%SZ' "${workflow}"; then
  fail "release build still embeds wall-clock time"
fi
if grep -Fq 'gh release edit' "${workflow}" "${publish_script}"; then
  fail "release policy must never edit an existing GitHub Release"
fi
if grep -Fq -- '--clobber' "${workflow}" "${publish_script}"; then
  fail "release policy must never clobber published assets"
fi

echo "release policy tests passed"
