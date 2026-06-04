# 开发环境

[English](development.md)

Tachyon Core 使用 `mise` 管理可复现工具链。

```bash
mise install
go test ./...
```

不要把 Go 直接安装到仓库内。运行时版本统一维护在 `.tool-versions` 中，确保贡献者和 CI 使用同一套工具链。

工具链版本应在确认 Go 官方下载页后跟随最新 stable 正式版。
