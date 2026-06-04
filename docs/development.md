# Development

[中文说明](development.zh-CN.md)

Tachyon Core uses `mise` for reproducible toolchains.

```bash
mise install
go test ./...
```

Do not install Go directly into the repository. Keep runtime versions in
`.tool-versions` so contributors and CI use the same toolchain.

Toolchain versions should track the latest stable Go release after checking
the official Go downloads page.
