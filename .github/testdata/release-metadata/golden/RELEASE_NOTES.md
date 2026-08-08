# Tachyon Core v9.8.7-alpha.6

## Release identity

- Version: `v9.8.7-alpha.6`
- Source commit: `0123456789abcdef0123456789abcdef01234567`
- Channel: alpha prerelease

## Compatibility

- Windows, macOS, and Linux on AMD64 or ARM64.
- Six platform ZIPs contain `tachyon-core` and `tachyonctl`.
- Windows `wintun.dll` is an external Prism-managed sidecar and is not bundled.

## Verification and release assets

Download `SHA256SUMS.txt` and verify the complete asset set before installation.
The bilingual notes are `RELEASE_NOTES.md` and `RELEASE_NOTES.zh-CN.md`. The
release also contains deterministic `BUILD_METADATA.json`, the verified
`WINTUN_SIDECAR_CONTRACT.json`, `EVIDENCE_MANIFEST.json`, and the sanitized Helper
evidence archive. The release workflow verifies the published release is immutable
and that GitHub asset digests and sizes match the local manifest.

## Alpha boundary

- `v9.8.7-alpha.6` is the **WFP Helper / Captured UDP Named Pipe v2 Preview**.
- It includes the Core-side authenticated Named Pipe v2 contract, Helper/Service
  preview contract, lease and registry controls, TGP bridge, lifecycle cleanup,
  and single-writer close hardening.
- This preview has **no real WFP callout**, no signed WFP driver, no kernel
  injection, no process capture, and no real game end-to-end (E2E) validation.
  The Helper evidence is deliberately fail-closed with `capture_provider=not_ready`.
- `wintun.dll` is managed by Prism from the official sidecar contract. Prism must
  refuse to start Core when the sidecar is missing or its SHA-256 does not match.

## Limitations

- Tachyon Core remains alpha software and is not stable or complete.
- Prism-managed system-proxy takeover remains disabled by default; Core does not
  modify host proxy settings.
- Client TUN auto-route and DNS hijack remain unsupported and are rejected by
  configuration validation.
- Real VPS, carrier/network, client, target-game UDP, and elevated Windows TUN
  validation remain required.
