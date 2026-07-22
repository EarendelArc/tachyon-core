# 发布流程

Tachyon Core 通过本仓库的 GitHub Actions 发布。当前 release 属于 alpha
质量：客户端 TUN 自动路由和 DNS hijack 当前不受支持，并会被配置校验拒绝；
Windows TUN 仍需要真实管理员环境验证。这些产物主要用于 Prism 托管下载和集成测试。

## 当前预览版本

当前已发布的预览标签是 `v0.1.0-alpha.20`。该 release 属于历史例外：GitHub Release
只有英文自动正文，且没有 release notes 资产。该 release 保持不可变，不会编辑或回填。

下述确定性双语契约从 `v0.1.0-alpha.20` 之后的 release 开始适用。中英文正文都会明确
alpha 限制；在将 Core 视为可用于生产前，仍需完成真实 VPS、真实客户端、运营商/网络、
目标游戏 UDP 以及具备管理员权限的 Windows TUN 验证。

`main` 分支可能包含比该 tag 更新的未发布提交。只有在 `go test ./...` 和跨平台构建矩阵通过后，才应该创建新的 release tag。

## 触发方式

推送版本 tag：

```bash
git tag v0.1.0-alpha.1
git push origin v0.1.0-alpha.1
```

也可以在 GitHub Actions 页面手动运行 `Release` workflow，并输入 tag。

## 双语发布契约

workflow 只从已验证 tag 及其完整源代码 commit SHA 派生发布元数据，不使用 GitHub
自动生成 release notes，并生成：

- `RELEASE_NOTES.md`：包含英文的发布标识、兼容性、安装、校验和 alpha 限制；
- `RELEASE_NOTES.zh-CN.md`：包含对应的简体中文内容；
- GitHub Release 正文：先英文、后简体中文，由上述两份文件组合而成。

生成过程不读取 workflow 实时时钟，也不依赖外部文本生成器。输入相同 tag、commit SHA
和六个 ZIP 时，notes 与 checksum manifest 必须逐字节一致。

CI 与本地 PowerShell 实现共同渲染 `.github/release-notes` 中的模板，并分别使用
`.github/testdata/release-metadata` 下同一套固定 fixture 与 golden 输出进行测试。模板、
编码、顺序或 checksum 格式发生漂移时，release policy 测试会失败。

如果只需要在本地验证产物而不发布到 GitHub，可以运行：

```powershell
scripts\build-release.ps1 -Tag v0.1.0-alpha.2 -OutputDir $env:TEMP\tachyon-core-release
```

Windows 本地构建不依赖 Bash。脚本解析当前完整 commit，并从该 commit 的 Git commit time
派生 `SOURCE_DATE_EPOCH`、写入二进制的 `BuildTime`、归档内条目时间和输出文件时间。若指定
tag 已存在，则该 tag 必须最终指向当前 `HEAD`；不一致时直接失败，避免生成误导性元数据。

六个 ZIP 生成后，本地脚本使用共享模板的 PowerShell 实现，因此输出目录同样满足双语
元数据契约。`SHA256SUMS.txt` 严格包含八项，顺序依次为英文 notes、简体中文 notes、
Windows AMD64/ARM64、macOS AMD64/ARM64、Linux AMD64/ARM64 ZIP。manifest 使用小写
SHA-256、文件名前两个空格、LF 换行且无 BOM。

## 产物

workflow 会构建以下 ZIP 资产：

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

release 还会包含 `RELEASE_NOTES.md`、`RELEASE_NOTES.zh-CN.md` 和
`SHA256SUMS.txt`。checksum manifest 同时覆盖六个 ZIP 与两份 notes。publisher 在任何
GitHub 写操作前校验完整 manifest，随后在 release 仍为 draft 时一次上传完整资产集，
最后只发布本次新建的 draft。若已存在同标签的 draft 或正式 release，流程会失败，不会
编辑或替换已有内容。

## Prism 下载约定

Prism 应按规范化平台选择资产：

| 运行环境 | 资产后缀 |
| --- | --- |
| Windows x64 | `windows_amd64` |
| Windows ARM64 | `windows_arm64` |
| macOS Intel | `darwin_amd64` |
| macOS Apple Silicon | `darwin_arm64` |
| Linux x64 | `linux_amd64` |
| Linux ARM64 | `linux_arm64` |

Prism 必须下载 `SHA256SUMS.txt`，要求所选压缩包恰好有一条 checksum 记录，校验后再
解压二进制文件并安装到自己的托管 `bin` 目录。下载完整 release 的操作者可运行
`sha256sum --check SHA256SUMS.txt`，一次校验全部压缩包与两份 notes。

## 服务端安装脚本约定

`scripts/install-server.sh` 与 `scripts/install-server-docker.sh` 都从
`EarendelArc/tachyon-core` GitHub Releases 下载匹配的 Linux ZIP 资产。
脚本的 `--version latest` 会读取 release 列表中的最新 tag，因此包含 alpha
预发布版本；生产环境如需可复现部署，应显式传入 `--version v0.1.0-alpha.14`
或更新后的固定 tag。

裸机脚本将二进制安装到 `/opt/tachyon` 并创建加固后的 systemd 服务。脚本可以代管
ufw；如果 SSH 使用非 22 端口，应传入 `--ssh-port PORT`，如果防火墙由云安全组、
nftables、firewalld 或自定义策略管理，应传入 `--no-firewall` 并自行放行端口。Docker
脚本会把下载的静态二进制放入 `/opt/tachyon-docker/bin`，再挂载到
`debian:bookworm-slim` 容器中运行，避免依赖尚未发布的 GHCR 镜像；Docker 部署不会修改
宿主机防火墙，并且有意使用 host network 来避免 UDP NAT/userland proxy 带来的额外抖动。

两个脚本都会在未提供 `TACHYON_PSK` 时生成新的 `tgp.auth.psk`。服务端 Relay
默认不会成为开放 UDP relay：安装脚本会从 `--allow-target` 参数或分号分隔的
`TACHYON_ALLOWED_TARGETS` 环境变量写入 `server.relay.allowed_targets`。条目格式示例：
`cidr=198.51.100.0/24,ports=27015-27050` 或
`domain=game.example.com,ports=27015`。如果未提供目标，生成配置会保持
`allowed_targets` 为空，Core 以安全 deny-all 模式运行。脚本会拒绝
`0.0.0.0/0`、`::/0` 和未显式填写端口的条目。生成配置也会写入 Relay 资源上限默认值：
`max_sessions`、`session_queue_size`、`handler_concurrency`、`max_flows` 和
`max_flows_per_session`。

裸机 systemd 服务以 `tachyon` 用户运行，只保留 `CAP_NET_BIND_SERVICE`，启用
`NoNewPrivileges`、系统路径只读、私有临时目录、受限地址族，并且只允许 Tachyon 日志目录
可写。Docker compose 部署启用只读 rootfs、`no-new-privileges`、`cap_drop: [ALL]`、
`cap_add: [NET_BIND_SERVICE]`、tmpfs 临时目录、配置校验健康检查和
`restart: unless-stopped`。

部署后请按对应模式运行 `scripts/verify-server.sh` 收集只读诊断，再继续使用真实客户端
和游戏 UDP 流量测试。
