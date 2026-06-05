# Release Process

Tachyon Core releases are published by GitHub Actions from this repository.
Releases are currently alpha-quality because Windows TUN and macOS PID tracking
are not complete yet, but the artifacts are useful for Prism-managed downloads
and integration testing.

## Trigger

Push a version tag:

```bash
git tag v0.1.0-alpha.1
git push origin v0.1.0-alpha.1
```

The `Release` workflow can also be started manually from GitHub Actions with a
tag input.

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
