#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
verify_script="${repo_root}/.github/scripts/verify-release-tag.sh"
prepare_script="${repo_root}/.github/scripts/prepare-release.sh"
publish_script="${repo_root}/.github/scripts/publish-release.sh"
workflow="${repo_root}/.github/workflows/release.yml"
testdata="${repo_root}/.github/testdata/release-metadata"
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
git -C "${source_repo}" tag --annotate v1.2.3 --message "wrong commit" "${first_commit}"

printf 'second\n' > "${source_repo}/payload.txt"
git -C "${source_repo}" commit --quiet -am "second"
second_commit=$(git -C "${source_repo}" rev-parse HEAD)
git -C "${source_repo}" tag --annotate v1.2.4 --message "unsigned release tag" "${second_commit}"
git -C "${source_repo}" tag v1.2.5 "${second_commit}"
git -C "${source_repo}" remote add origin "${remote}"
git -C "${source_repo}" push --quiet origin HEAD:refs/heads/main refs/tags/v1.2.3 refs/tags/v1.2.4 refs/tags/v1.2.5

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

expect_failure \
  "lightweight tag at expected commit" \
  "must be an annotated tag object; fetched object type is commit" \
  run_gate "${checkout}" v1.2.5 "${second_commit}"

output_file="${tmp_dir}/github-output"
run_gate "${checkout}" v1.2.4 "${second_commit}" "${output_file}"
grep -Fqx "tag=v1.2.4" "${output_file}" || fail "correct tag output is missing"
grep -Fqx "commit=${second_commit}" "${output_file}" || fail "correct commit output is missing"
grep -Fqx "verification=annotated-tag" "${output_file}" || fail "unsigned annotated tag verification was not explicit"

golden_release="${tmp_dir}/golden-release"
mkdir -p "${golden_release}"
python3 "${repo_root}/.github/scripts/create-release-policy-fixtures.py" \
  --release-dir "${golden_release}" \
  --evidence-dir "${tmp_dir}/golden-evidence" \
  --version v9.8.7-alpha.6 \
  --commit 0123456789abcdef0123456789abcdef01234567
python3 "${repo_root}/.github/scripts/generate-build-metadata.py" \
  --version v9.8.7-alpha.6 \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --source-date-epoch 0 \
  --build-time 1970-01-01T00:00:00Z \
  --go-version go1.test \
  --release-directory "${golden_release}" \
  --output "${golden_release}/BUILD_METADATA.json"
cp "${repo_root}/.github/wintun/WINTUN_SIDECAR_CONTRACT.json" "${golden_release}/WINTUN_SIDECAR_CONTRACT.json"
python3 "${repo_root}/.github/scripts/generate-evidence-manifest.py" \
  --directory "${tmp_dir}/golden-evidence" \
  --version v9.8.7-alpha.6 \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --run-id 1 \
  --run-attempt 1 \
  --source-date-epoch 0 \
  --output-directory "${golden_release}"
bash "${prepare_script}" \
  v9.8.7-alpha.6 \
  0123456789abcdef0123456789abcdef01234567 \
  "${golden_release}"
for golden_name in RELEASE_NOTES.md RELEASE_NOTES.zh-CN.md SHA256SUMS.txt; do
  cmp "${golden_release}/${golden_name}" "${testdata}/golden/${golden_name}" || \
    fail "Bash output differs from shared golden ${golden_name}"
done
[[ $(wc -l < "${golden_release}/SHA256SUMS.txt") -eq 12 ]] || fail "golden checksum manifest must contain exactly twelve entries"
[[ $(find "${golden_release}" -maxdepth 1 -type f | wc -l) -eq 13 ]] || fail "GitHub release fixture must contain exactly thirteen assets"

printf 'unexpected\n' > "${golden_release}/unexpected.txt"
expect_failure \
  "undeclared release asset" \
  "release directory contains an unexpected asset set" \
  bash "${prepare_script}" v9.8.7-alpha.6 0123456789abcdef0123456789abcdef01234567 "${golden_release}"
rm "${golden_release}/unexpected.txt"

TACHYON_RELEASE_POLICY_TEST=1 python3 "${repo_root}/.github/scripts/test-release-assets-policy.py"
python3 "${repo_root}/.github/scripts/test-published-release-policy.py"

fake_bin="${tmp_dir}/fake-bin"
fake_state="${tmp_dir}/fake-gh-state"
fake_log="${tmp_dir}/fake-gh-log"
fake_body="${tmp_dir}/fake-gh-body"
release_assets="${tmp_dir}/release-assets"
mkdir -p "${fake_bin}" "${release_assets}"
python3 "${repo_root}/.github/scripts/create-release-policy-fixtures.py" \
  --release-dir "${release_assets}" \
  --evidence-dir "${tmp_dir}/release-evidence" \
  --version v1.2.4 \
  --commit "${second_commit}" \
  --run-id 2 \
  --run-attempt 1
python3 "${repo_root}/.github/scripts/generate-build-metadata.py" \
  --version v1.2.4 \
  --commit "${second_commit}" \
  --source-date-epoch 0 \
  --build-time 1970-01-01T00:00:00Z \
  --go-version go1.test \
  --release-directory "${release_assets}" \
  --output "${release_assets}/BUILD_METADATA.json"
cp "${repo_root}/.github/wintun/WINTUN_SIDECAR_CONTRACT.json" "${release_assets}/WINTUN_SIDECAR_CONTRACT.json"
python3 "${repo_root}/.github/scripts/generate-evidence-manifest.py" \
  --directory "${tmp_dir}/release-evidence" \
  --version v1.2.4 \
  --commit "${second_commit}" \
  --run-id 2 \
  --run-attempt 1 \
  --source-date-epoch 0 \
  --output-directory "${release_assets}"

bash "${prepare_script}" v1.2.4 "${second_commit}" "${release_assets}"
cp "${release_assets}/RELEASE_NOTES.md" "${tmp_dir}/RELEASE_NOTES.first.md"
cp "${release_assets}/RELEASE_NOTES.zh-CN.md" "${tmp_dir}/RELEASE_NOTES.zh-CN.first.md"
cp "${release_assets}/SHA256SUMS.txt" "${tmp_dir}/SHA256SUMS.first.txt"
bash "${prepare_script}" v1.2.4 "${second_commit}" "${release_assets}"
cmp "${tmp_dir}/RELEASE_NOTES.first.md" "${release_assets}/RELEASE_NOTES.md" || fail "English release notes are not deterministic"
cmp "${tmp_dir}/RELEASE_NOTES.zh-CN.first.md" "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese release notes are not deterministic"
cmp "${tmp_dir}/SHA256SUMS.first.txt" "${release_assets}/SHA256SUMS.txt" || fail "checksum manifest is not deterministic"

grep -Fq "Version: \`v1.2.4\`" "${release_assets}/RELEASE_NOTES.md" || fail "English notes omit the version"
grep -Fq "Source commit: \`${second_commit}\`" "${release_assets}/RELEASE_NOTES.md" || fail "English notes omit the commit"
grep -Fq '## Compatibility' "${release_assets}/RELEASE_NOTES.md" || fail "English notes omit compatibility"
grep -Fq '## Verification and release assets' "${release_assets}/RELEASE_NOTES.md" || fail "English notes omit verification"
grep -Fq '## Limitations' "${release_assets}/RELEASE_NOTES.md" || fail "English notes omit alpha limitations"
grep -Fq 'WFP Helper / Captured UDP Named Pipe v2 Preview' "${release_assets}/RELEASE_NOTES.md" || fail "English notes omit WFP Helper preview boundary"
grep -Fq 'no real WFP callout' "${release_assets}/RELEASE_NOTES.md" || fail "English notes omit WFP limitation"
grep -Fq "版本：\`v1.2.4\`" "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese notes omit the version"
grep -Fq "源代码提交：\`${second_commit}\`" "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese notes omit the commit"
grep -Fq '## 兼容性' "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese notes omit compatibility"
grep -Fq '## 校验与发布资产' "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese notes omit verification"
grep -Fq '## 限制' "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese notes omit alpha limitations"
grep -Fq 'WFP Helper / Captured UDP Named Pipe v2 Preview' "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese notes omit WFP Helper preview boundary"
grep -Fq '不包含真实 WFP callout' "${release_assets}/RELEASE_NOTES.zh-CN.md" || fail "Chinese notes omit WFP limitation"
grep -Eq '^[0-9a-f]{64}  RELEASE_NOTES.md$' "${release_assets}/SHA256SUMS.txt" || fail "English notes are not checksummed"
grep -Eq '^[0-9a-f]{64}  RELEASE_NOTES.zh-CN.md$' "${release_assets}/SHA256SUMS.txt" || fail "Chinese notes are not checksummed"
(cd "${release_assets}" && sha256sum --check --strict SHA256SUMS.txt) >/dev/null || fail "prepared asset checksums do not verify"

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
  previous=""
  for argument in "$@"; do
    if [[ "${previous}" == "--notes-file" ]]; then
      cp "${argument}" "${FAKE_GH_BODY}"
    fi
    previous="${argument}"
  done
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
  local prerelease=${2:-true}
  local version=${3:-v1.2.4}
  PATH="${fake_bin}:${PATH}" \
    FAKE_GH_MODE="${mode}" \
    FAKE_GH_STATE="${fake_state}" \
    FAKE_GH_LOG="${fake_log}" \
    FAKE_GH_BODY="${fake_body}" \
    GITHUB_REPOSITORY="tachyon-space/tachyon-core" \
    bash "${publish_script}" "${version}" "${second_commit}" "${prerelease}" "${release_assets}"
}

rm -f "${fake_state}" "${fake_log}" "${fake_body}"
expect_failure \
  "non-prerelease publication" \
  "only prerelease publication is supported; prerelease must be true" \
  run_publish happy false v1.2.4-alpha.24
[[ ! -f "${fake_log}" ]] || fail "prerelease=false reached the GitHub API"

rm -f "${fake_state}" "${fake_log}" "${fake_body}"
expect_failure "existing release" "already exists; refusing to edit or replace" run_publish existing
! grep -Eq '^release (create|upload)' "${fake_log}" || fail "existing release path performed a write"

rm -f "${fake_state}" "${fake_log}" "${fake_body}"
run_publish happy
grep -Fq 'release create v1.2.4 --draft --verify-tag' "${fake_log}" || fail "release was not created as a verified draft"
grep -Fq -- '--prerelease' "${fake_log}" || fail "release was not created as a prerelease"
[[ $(grep -Fc 'release upload v1.2.4' "${fake_log}") -eq 1 ]] || fail "assets were not uploaded exactly once"
grep -Fq 'RELEASE_NOTES.md' "${fake_log}" || fail "English notes were not uploaded"
grep -Fq 'RELEASE_NOTES.zh-CN.md' "${fake_log}" || fail "Chinese notes were not uploaded"
grep -Fq 'SHA256SUMS.txt' "${fake_log}" || fail "checksum manifest was not uploaded"
grep -Fq 'api --method PATCH repos/tachyon-space/tachyon-core/releases/123' "${fake_log}" || fail "draft was not published through its release ID"
{
  cat "${release_assets}/RELEASE_NOTES.md"
  printf '\n\n---\n\n'
  cat "${release_assets}/RELEASE_NOTES.zh-CN.md"
} > "${tmp_dir}/expected-release-body.md"
cmp "${tmp_dir}/expected-release-body.md" "${fake_body}" || fail "GitHub Release body is not the deterministic bilingual composition"

rm -f "${fake_state}" "${fake_log}" "${fake_body}"
expect_failure "asset upload" "simulated upload failure" run_publish upload-fail
grep -Fq 'api --method DELETE repos/tachyon-space/tachyon-core/releases/123' "${fake_log}" || fail "failed upload did not clean up its draft"
[[ ! -f "${fake_state}" ]] || fail "failed upload left the fake draft behind"

printf 'tampered\n' >> "${release_assets}/RELEASE_NOTES.md"
rm -f "${fake_state}" "${fake_log}" "${fake_body}"
expect_failure "tampered release metadata" "release asset checksum verification failed" run_publish happy
[[ ! -f "${fake_log}" ]] || fail "checksum failure reached the GitHub API"
bash "${prepare_script}" v1.2.4 "${second_commit}" "${release_assets}"

rm "${release_assets}/RELEASE_NOTES.zh-CN.md"
rm -f "${fake_state}" "${fake_log}" "${fake_body}"
expect_failure "missing Chinese notes" "Simplified Chinese release notes are missing" run_publish happy
[[ ! -f "${fake_log}" ]] || fail "missing bilingual metadata reached the GitHub API"
bash "${prepare_script}" v1.2.4 "${second_commit}" "${release_assets}"

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
grep -Fq 'bash .github/scripts/prepare-release.sh "${version}" "${VERIFIED_COMMIT}" release' "${workflow}" || fail "workflow does not use deterministic release metadata preparation"
grep -Fq 'echo "prerelease=true" >> "${GITHUB_OUTPUT}"' "${workflow}" || fail "release workflow does not force prerelease metadata"
if grep -Fq 'inputs.prerelease' "${workflow}"; then
  fail "workflow_dispatch still exposes a formal-release path"
fi
grep -Fq '[[ "${prerelease}" == "true" ]]' "${publish_script}" || fail "publisher does not fail closed on prerelease=false"
grep -Fq '[[ ${#assets[@]} -eq 13 ]]' "${publish_script}" || fail "publisher does not enforce thirteen GitHub assets"
grep -Fq '[[ ${#expected_checksum_entries[@]} -eq 12 ]]' "${publish_script}" || fail "publisher does not enforce twelve checksum entries"
grep -Fq 'sha256sum --check --strict SHA256SUMS.txt' "${publish_script}" || fail "publisher does not verify the complete checksum manifest"
grep -Fq 'gh api "repos/${repository}/releases/tags/${version}"' "${repo_root}/.github/scripts/verify-published-release.sh" || fail "published release verification does not use the real GitHub API"
grep -Fq 'validate-published-release.py' "${repo_root}/.github/scripts/verify-published-release.sh" || fail "published release verification does not use the strict validator"
if grep -Eq 'FIXTURE|fixture|TACHYON_RELEASE_JSON' "${repo_root}/.github/scripts/verify-published-release.sh"; then
  fail "production published release verification contains a fixture bypass"
fi
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
[[ ! -d "${repo_root}/.github/scripts/__pycache__" ]] || fail "release policy tests left a Python bytecode cache in the worktree"

echo "release policy tests passed"
