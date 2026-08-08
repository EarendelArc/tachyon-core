# Release Process

Tachyon Core releases are published by GitHub Actions from this repository. The
current release line is alpha and must not be described as production-ready: the
WFP Helper is preview-only, and no real process capture or game E2E has been
validated.

## Release boundary

The next release is prepared as `v0.1.0-alpha.24` from the verified commit. It is
the **WFP Helper / Captured UDP Named Pipe v2 Preview**. The release may contain
Helper and Windows Service preview contracts, but it contains no real WFP callout,
no signed driver, no kernel injection, no process capture, and no real game E2E.
These statements must remain synchronized in both release-note files and both
changelogs.

## Deterministic assets

The workflow builds six ZIPs:

- `tachyon-core_<tag>_windows_amd64.zip`
- `tachyon-core_<tag>_windows_arm64.zip`
- `tachyon-core_<tag>_darwin_amd64.zip`
- `tachyon-core_<tag>_darwin_arm64.zip`
- `tachyon-core_<tag>_linux_amd64.zip`
- `tachyon-core_<tag>_linux_arm64.zip`

It also publishes `RELEASE_NOTES.md`, `RELEASE_NOTES.zh-CN.md`,
`BUILD_METADATA.json`, `WINTUN_SIDECAR_CONTRACT.json`, `EVIDENCE_MANIFEST.json`,
the deterministic `tachyon-helper-evidence_<tag>.tar.gz`, and `SHA256SUMS.txt`.
The GitHub Release therefore contains exactly thirteen assets. `SHA256SUMS.txt`
covers the other twelve assets and does not contain an entry for itself.

`BUILD_METADATA.json` records the tag, full commit, source-date epoch, build time,
Go version, every target OS/architecture, and each ZIP and embedded binary SHA-256.
The build uses the verified commit time as `SOURCE_DATE_EPOCH`; no workflow wall
clock is used for release metadata.

## Helper evidence

The Windows CI job uploads a sanitized Helper evidence directory. The release job
downloads the evidence from the same successful workflow run, validates the inner
manifest commit/run identity and file hashes, rejects secret-like fields, and
packages it into a deterministic archive. `EVIDENCE_MANIFEST.json` records the
source commit, run identity, archive hash, and the fail-closed `not_ready` scope.
It is not proof of WFP capture, process attribution, injection, or game E2E.

## Wintun sidecar

Wintun is not bundled by Core. Prism owns the external sidecar supply chain and
must verify the contract before launch. The release workflow fetches the official
Wintun page and archive, checks the pinned current stable version and archive/DLL
SHA-256 values, then emits `WINTUN_SIDECAR_CONTRACT.json`. Any mismatch or inability
to verify fails closed. Prism must refuse to start Core when the sidecar is absent
or mismatched.

The pinned Wintun 0.14.1 DLL sizes are `427552` bytes for Windows AMD64 and
`222488` bytes for Windows ARM64. Both PowerShell preparation paths invoke the
same official generator and release validator as CI. The offline fixture option
is restricted to policy tests and cannot bypass production network verification.

## Publication gates

The remote tag gate accepts only a real annotated tag object whose peeled commit
matches the verified checkout. A correctly targeted lightweight tag is still rejected.

The current alpha release pipeline is prerelease-only. Tag pushes and manual
`workflow_dispatch` runs both force `prerelease=true`; there is no manual formal-release
input. The publisher rejects every other value before its first GitHub API operation.

Before publishing, the workflow requires the verified tag, green Linux and Windows
CI, six platform ZIPs, all bilingual notes, all manifests, and a strict SHA-256
check. It creates one draft, uploads the complete asset set once, and publishes
only that draft. The final step calls `verify-published-release.sh`, which checks:

- the release is not a draft, is a prerelease, and is immutable;
- the release target commit is the verified commit;
- the remote asset names exactly equal the local asset set;
- remote asset sizes and GitHub digests match local files.

The tag protection ruleset must remain active for `v*`. Do not replace an existing
release or mutate an immutable release. Never create or push a tag as part of local
release preparation.

The local builder accepts only an existing annotated tag that peels to the
checked-out `HEAD` or the explicitly supplied full commit. A missing tag,
lightweight tag, or commit mismatch fails before building.

## Local preparation

The local PowerShell builder is a packaging aid. A publishable candidate must carry
validated CI evidence; it must not synthesize release eligibility from a local fake
capture. Use the GitHub workflow for the authoritative candidate, then run the
policy tests and cross-platform build checks before authorizing a tag.
