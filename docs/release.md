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

All release ZIPs, the Helper evidence PAX tar/gzip archive, bilingual notes, and
`SHA256SUMS.txt` are produced by shared Python production generators on Bash and
PowerShell paths. ZIP entries are stored without compressor-dependent output and
carry a UTC-clamped timestamp, bytewise UTF-8 path order, no extra fields, and
normalized `0644`/`0755` modes. Evidence tar members use the exact source epoch,
UID/GID `0`, owner/group `root`, mode `0644`, empty per-member PAX headers, and a
gzip header with no host filename. Host filesystem ownership, timestamps, mode,
locale, and timezone never enter release bytes.

`.github/scripts/test-reproducible-release.py` regenerates all thirteen fixture
assets twice after deliberately changing host metadata and creation order. Ubuntu
and Windows CI require byte-for-byte equality plus the same committed golden
`EVIDENCE_MANIFEST.json`, evidence archive, and `SHA256SUMS.txt`. Golden files may
only be refreshed with that fixture's explicit `--update-golden` mode, which calls
the production generators. Synthetic Helper evidence is written as explicit UTF-8
LF text on every host; the reproducibility fixture rejects CR bytes and missing
terminal newlines before packaging so platform newline translation cannot alter
inner hashes or the referenced archive. The Ubuntu reproducibility step uses
`always()` so an earlier policy assertion cannot suppress this independent byte
evidence; its own failure still fails the job.

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

CI keeps release policy, Linux installer lifecycle evidence, ordinary Go tests,
and Go race tests in independent jobs. A release-policy failure therefore cannot
hide flock, signal rollback, or SIGKILL recovery evidence; the final required job
still fails unless every independent job, Windows test, and six-platform build is
successful.

The tag-triggered Release workflow independently reruns the complete Bash release
policy, the two-run thirteen-asset byte reproducibility fixture, and the real Linux
installer lifecycle fixture against the verified commit. Its `prepublish-gate`
runs with `always()` and checks every prerequisite result explicitly. Publication
cannot start unless tag verification, policy, lifecycle, Linux and Windows tests,
and all six builds report `success`.

Linux lifecycle fixtures launch each real installer through the repository-owned
`fixture_process_launcher.py`. Before `exec`, the launcher creates a new session,
resets INT, TERM, and HUP to `SIG_DFL`, and writes a mode-0600 JSON audit proving
PID/PGID/SID identity and signal dispositions. Every scenario has an eight-second
inner timeout; failures print bounded diagnostics and do not prevent later TERM,
HUP, lock-contention, or SIGKILL recovery scenarios from running.

The mocked `systemctl start` fault contract is phase- and identity-specific: each
injection names an exact call number, expected installed unit (`new` or `old`), and
transaction phase. The new-deployment start-failure case therefore allows rollback
to restart the old service. A separate case intentionally fails that old-service
restart, requires the production rollback to retain its journal and phase, then
proves a fresh recovery process can restart the old service and remove the journal.

The remote tag gate accepts only a real annotated tag object whose peeled commit
matches the verified checkout. A correctly targeted lightweight tag is still rejected.

The current alpha release pipeline is prerelease-only. Tag pushes and manual
`workflow_dispatch` runs both force `prerelease=true`; there is no manual formal-release
input. The publisher rejects every other value before its first GitHub API operation.
The repository secret `RELEASE_SETTINGS_TOKEN` must be a fine-grained token with
repository Administration read permission. Before creating even a draft, the
publisher uses GitHub REST API version `2026-03-10` to prove that repository
immutable releases are enabled; a missing token, disabled setting, permission
failure, or ambiguous response fails before any release write.

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
