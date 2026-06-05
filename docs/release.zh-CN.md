# 发布流程

Tachyon Core 通过本仓库的 GitHub Actions 发布。当前 release 属于 alpha
质量：Windows TUN 已经具备动态 `wintun.dll` 后端，但仍需要真实管理员环境验证。
这些产物已经可以用于 Prism 托管下载和集成测试。

## 触发方式

推送版本 tag：

```bash
git tag v0.1.0-alpha.1
git push origin v0.1.0-alpha.1
```

也可以在 GitHub Actions 页面手动运行 `Release` workflow，并输入 tag。

## 产物

workflow 会构建以下 ZIP 资产：

- `tachyon-core_<tag>_windows_386.zip`
- `tachyon-core_<tag>_windows_amd64.zip`
- `tachyon-core_<tag>_windows_arm64.zip`
- `tachyon-core_<tag>_darwin_amd64.zip`
- `tachyon-core_<tag>_darwin_arm64.zip`
- `tachyon-core_<tag>_linux_amd64.zip`
- `tachyon-core_<tag>_linux_arm64.zip`

每个压缩包包含：

- `tachyon-core` 或 `tachyon-core.exe`
- `tachyonctl` 或 `tachyonctl.exe`
- `README.md`
- `README.zh-CN.md`

Windows 压缩包暂不内置 `wintun.dll`。Prism 在 Windows 上启动 Core 前，必须检查
配置的 `tachyon-core.exe` 同目录是否存在 `wintun.dll`。

release 还会包含 `SHA256SUMS.txt`，供 Prism 下载后校验。

## Prism 下载约定

Prism 应按规范化平台选择资产：

| 运行环境 | 资产后缀 |
| --- | --- |
| Windows x86 | `windows_386` |
| Windows x64 | `windows_amd64` |
| Windows ARM64 | `windows_arm64` |
| macOS Intel | `darwin_amd64` |
| macOS Apple Silicon | `darwin_arm64` |
| Linux x64 | `linux_amd64` |
| Linux ARM64 | `linux_arm64` |

Prism 必须下载 `SHA256SUMS.txt`，校验选中的压缩包，解压二进制文件，并安装到
自己的托管 `bin` 目录。
