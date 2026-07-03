# Release Process

Tachyon Core releases are published by GitHub Actions from this repository.
Releases are currently alpha-quality: Windows TUN has a dynamic `wintun.dll`
backend, but it still needs real elevated-host validation. The artifacts are
useful for Prism-managed downloads and integration testing.

## Current Preview

The current preview release is
`v0.1.0-alpha.12` (preview tag preparation). It includes PSK-authenticated TGP
handshakes with server-side PSK required by default, safe deny-all server relay
ACLs, wildcard/empty-port ACL rejection, multi-session relay handling,
source-address relay demux, fail-closed handling for unknown non-handshake UDP,
relay resource limits, persistent UDP relay pools with asynchronous upstream
responses, TGP-only client safe defaults, and bare-metal/Docker installer
guidance for `allowed_targets`.

Known limitations for this preview: relay path rebind/migration is fail-closed
until an authenticated rebind control path exists, Windows TUN still needs
elevated validation on real Windows hosts, real VPS/game-link relay validation
is still pending, and domain ACLs are resolved at Core startup rather than
dynamically tracked.

The `main` branch may contain newer unreleased changes after this tag. Create a
new release tag only after `go test ./...` and the cross-platform build matrix
pass.

## Trigger

Push a version tag:

```bash
git tag v0.1.0-alpha.1
git push origin v0.1.0-alpha.1
```

The `Release` workflow can also be started manually from GitHub Actions with a
tag input.

For local verification without publishing to GitHub, run:

```powershell
scripts\build-release.ps1 -Tag v0.1.0-alpha.2 -OutputDir $env:TEMP\tachyon-core-release
```

## Assets

The workflow builds these ZIP assets:

- `tachyon-core_<tag>_windows_386.zip`
- `tachyon-core_<tag>_windows_amd64.zip`
- `tachyon-core_<tag>_windows_arm64.zip`
- `tachyon-core_<tag>_darwin_amd64.zip`
- `tachyon-core_<tag>_darwin_arm64.zip`
- `tachyon-core_<tag>_linux_amd64.zip`
- `tachyon-core_<tag>_linux_arm64.zip`

Each archive contains:

- `tachyon-core` or `tachyon-core.exe`
- `tachyonctl` or `tachyonctl.exe`
- `README.md`
- `README.zh-CN.md`

Windows archives do not bundle `wintun.dll` yet. Prism must verify that
`wintun.dll` exists next to the configured `tachyon-core.exe` before starting
Core on Windows.

The release also includes `SHA256SUMS.txt` for Prism-side verification.

## Prism Contract

Prism should select assets by normalized platform:

| Runtime | Asset suffix |
| --- | --- |
| Windows x86 | `windows_386` |
| Windows x64 | `windows_amd64` |
| Windows ARM64 | `windows_arm64` |
| macOS Intel | `darwin_amd64` |
| macOS Apple Silicon | `darwin_arm64` |
| Linux x64 | `linux_amd64` |
| Linux ARM64 | `linux_arm64` |

Prism must download `SHA256SUMS.txt`, verify the selected archive, extract the
binary, and install it into its managed `bin` directory.

## Server Installer Contract

The bare-metal and Docker server installers consume the same release ZIP assets:

- `scripts/install-server.sh` downloads `tachyon-core_<tag>_linux_<arch>.zip`,
  extracts `tachyon-core`, installs it under `/opt/tachyon`, and creates a
  systemd service.
- `scripts/install-server-docker.sh` downloads the same Linux ZIP, stores the
  binary under `/opt/tachyon-docker/bin`, and mounts it into a
  `debian:bookworm-slim` container. The Docker deployment does not require a
  GHCR image.

Both scripts resolve `--version latest` from the releases list instead of the
GitHub `latest` endpoint so alpha prereleases remain deployable during the
current development phase.

Both scripts generate a fresh `tgp.auth.psk` unless `TACHYON_PSK` is supplied.
The server relay does not become an open UDP relay by default: installers write
`server.relay.allowed_targets` from `--allow-target` entries or the
semicolon-separated `TACHYON_ALLOWED_TARGETS` environment variable. Accepted
entries look like `cidr=198.51.100.0/24,ports=27015-27050` or
`domain=game.example.com,ports=27015`. If no target is supplied, the generated
config keeps `allowed_targets` empty and Core runs in safe deny-all mode. The
installers reject `0.0.0.0/0`, `::/0`, and entries without explicit ports.
Generated configs also include the relay resource-limit defaults
(`max_sessions`, `session_queue_size`, `handler_concurrency`, `max_flows`, and
`max_flows_per_session`).
