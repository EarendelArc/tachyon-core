# 发布流程

Tachyon Core 通过本仓库的 GitHub Actions 发布。当前 release 属于 alpha
质量：Windows TUN 已经具备动态 `wintun.dll` 后端，但仍需要真实管理员环境验证。
这些产物已经可以用于 Prism 托管下载和集成测试。

## 当前预览版本

当前预览版是
`v0.1.0-alpha.13`（预发布 tag 准备）。该版本延续 alpha.12 中
PSK 认证、服务端 relay 默认 deny-all 的安全口径，并新增非破坏性服务端验收脚本
`scripts/verify-server.sh`。脚本可检查裸机 systemd 部署、Docker Compose 部署以及
本地 config/binary 组合，输出服务状态、配置校验、监听配置和脱敏后的
`allowed_targets` 摘要，并避免打印 `tgp.auth.psk` 原文。CI 也会对该脚本运行
bash 自检。

该预览版的已知限制：`scripts/verify-server.sh` 只是 alpha 验收辅助，不能替代
真实 VPS、Docker 主机和目标游戏 UDP 链路验证；relay 路径迁移/重绑定在加入
authenticated rebind 控制路径前仍为 fail-closed；Windows TUN 仍需真实 Windows
管理员环境验证；domain ACL 在 Core 启动时解析，暂不动态追踪。

`main` 分支可能包含比该 tag 更新的未发布提交。只有在 `go test ./...` 和跨平台构建矩阵通过后，才应该创建新的 release tag。

## 触发方式

推送版本 tag：

```bash
git tag v0.1.0-alpha.1
git push origin v0.1.0-alpha.1
```

也可以在 GitHub Actions 页面手动运行 `Release` workflow，并输入 tag。

如果只需要在本地验证产物而不发布到 GitHub，可以运行：

```powershell
scripts\build-release.ps1 -Tag v0.1.0-alpha.2 -OutputDir $env:TEMP\tachyon-core-release
```

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

## 服务端安装脚本约定

`scripts/install-server.sh` 与 `scripts/install-server-docker.sh` 都从
`EarendelArc/tachyon-core` GitHub Releases 下载匹配的 Linux ZIP 资产。
脚本的 `--version latest` 会读取 release 列表中的最新 tag，因此包含 alpha
预发布版本；生产环境如需可复现部署，应显式传入 `--version v0.1.0-alpha.13`
或更新后的固定 tag。

裸机脚本将二进制安装到 `/opt/tachyon` 并创建 systemd 服务；Docker 脚本会把
下载的静态二进制放入 `/opt/tachyon-docker/bin`，再挂载到
`debian:bookworm-slim` 容器中运行，避免依赖尚未发布的 GHCR 镜像。

两个脚本都会在未提供 `TACHYON_PSK` 时生成新的 `tgp.auth.psk`。服务端 Relay
默认不会成为开放 UDP relay：安装脚本会从 `--allow-target` 参数或分号分隔的
`TACHYON_ALLOWED_TARGETS` 环境变量写入 `server.relay.allowed_targets`。条目格式示例：
`cidr=198.51.100.0/24,ports=27015-27050` 或
`domain=game.example.com,ports=27015`。如果未提供目标，生成配置会保持
`allowed_targets` 为空，Core 以安全 deny-all 模式运行。脚本会拒绝
`0.0.0.0/0`、`::/0` 和未显式填写端口的条目。生成配置也会写入 Relay 资源上限默认值：
`max_sessions`、`session_queue_size`、`handler_concurrency`、`max_flows` 和
`max_flows_per_session`。
