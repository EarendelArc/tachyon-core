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

[[ "${repository}" == */* ]] || die "GITHUB_REPOSITORY must identify owner/repository"
[[ -d "${release_dir}" ]] || die "release directory does not exist"

release_json=$(gh api "repos/${repository}/releases/tags/${version}") || die "could not read published release"
TACHYON_RELEASE_JSON="$release_json" python3 - "${version}" "${commit}" "${release_dir}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

version, commit, release_dir = sys.argv[1:]
release = json.loads(os.environ["TACHYON_RELEASE_JSON"])
if release.get("tag_name") != version:
    raise SystemExit("tag name mismatch")
if release.get("draft") is not False:
    raise SystemExit("release is still a draft")
if release.get("prerelease") is not True:
    raise SystemExit("release is not marked prerelease")
if release.get("immutable") is not True:
    raise SystemExit("release is not immutable")
if str(release.get("target_commitish", "")).lower() != commit.lower():
    raise SystemExit("release target commit mismatch")

root = pathlib.Path(release_dir)
expected = {
    path.name: path
    for path in root.iterdir()
    if path.is_file()
    and path.name not in {"RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md"}
}
expected["RELEASE_NOTES.md"] = root / "RELEASE_NOTES.md"
expected["RELEASE_NOTES.zh-CN.md"] = root / "RELEASE_NOTES.zh-CN.md"
expected["SHA256SUMS.txt"] = root / "SHA256SUMS.txt"
remote = {asset["name"]: asset for asset in release.get("assets", [])}
if set(remote) != set(expected):
    raise SystemExit(f"release asset set mismatch: remote={sorted(remote)} expected={sorted(expected)}")

for name, path in expected.items():
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if remote[name].get("digest") != f"sha256:{digest}":
        raise SystemExit(f"remote digest mismatch: {name}")
    if remote[name].get("size") != path.stat().st_size:
        raise SystemExit(f"remote size mismatch: {name}")
print(f"verified immutable release {version} at {commit} with {len(expected)} assets")
PY
