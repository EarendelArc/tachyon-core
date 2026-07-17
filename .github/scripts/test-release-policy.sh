#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
verify_script="${repo_root}/.github/scripts/verify-release-tag.sh"
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

checkout_count=$(grep -Fc 'ref: ${{ needs.verify_tag.outputs.commit }}' "${workflow}")
[[ ${checkout_count} -ge 4 ]] || fail "release jobs are not all pinned to the verified commit"
gate_count=$(grep -Fc 'bash .github/scripts/verify-release-tag.sh' "${workflow}")
[[ ${gate_count} -ge 2 ]] || fail "initial and pre-publish tag gates are both required"
grep -Fq -- '--target "${COMMIT}"' "${workflow}" || fail "release target is not pinned to the verified commit"
grep -Fq -- '--verify-tag' "${workflow}" || fail "release creation does not require an existing tag"
grep -Fq 'EXPECTED_TAG_OBJECT: ${{ needs.verify_tag.outputs.tag_object }}' "${workflow}" || fail "pre-publish gate does not pin the tag object"

echo "release policy tests passed"
