# Tachyon Core

[English](README.md)

Tachyon Core 是 Tachyon 游戏协议的无头传输核心。它的角色类似 `xray-core`：它是一个独立网络核心，使用显式 JSON 配置，但协议目标是低延迟、低丢包的游戏 UDP 流量，而不是通用 TCP 代理。

```bash
# 只验证配置，不启动守护进程
tachyon-core validate --config client.json

# 启动核心守护进程
tachyon-core run --config client.json
tachyon-core run --config server.json

# 检查正在运行的 Core 是否健康
tachyonctl health
tachyonctl health --addr 127.0.0.1:55123
```

## 设计边界

- Prism 负责订阅获取、订阅解析、节点选择、Xray 生命周期、Xray JSON 生成、游戏配置管理、启动器扫描和桌面端总控编排。
- Core 负责 Tachyon 协议传输：数据包接管、基于进程的游戏路由、TGP 客户端传输和 TGP 服务端 Relay 行为。
- Tachyon Core 内部没有 Xray 的运行时或编译期依赖。
- TCP 代理流量属于 Prism/Xray；UDP 游戏流量属于 Tachyon Core/TGP。
- 客户端 TUN 默认采用 TGP-only 安全模式：`auto_route` 和 `dns_hijack`
  默认关闭，只有 Prism 或手写配置显式启用时才会接管全局路由/DNS。
- JSON 是 Core 的标准配置格式。早期 YAML 文件仅作为开发兼容格式保留。
- Core JSON 中的相对文件路径会以当前加载的配置文件所在目录为基准解析。

## 架构

```text
客户端模式
  TUN 设备 -> PID 追踪器 -> 路由引擎
    UDP 游戏流量 -> TGP 客户端会话
    TCP/代理流量 -> Core 忽略，由 Prism/Xray 负责

服务端模式
  UDP 监听器 -> TGP Relay -> 真实游戏服务器
```

## 实现状态

Tachyon Core 还不是生产完成版本。协议和管道已经可以用于 alpha 集成。Windows TUN 现在有 alpha 级动态 `wintun.dll` 后端，但仍需要在真实 Windows 主机上以管理员权限创建适配器进行运行时验证。

| 领域 | 状态 |
| --- | --- |
| 统一 client/server CLI | 完成 |
| JSON 配置加载和生成 | 完成 |
| Core JSON 内嵌 Prism 游戏配置 | 完成 |
| 基于进程的路由配置 | 完成 |
| 本地 HTTP 路由桥兼容层 | 完成 |
| tachyonctl health CLI | 完成 |
| tachyon-core validate 干运行 | 完成 |
| Linux TUN 和 PID 追踪 | 完成 |
| Windows PID 追踪 | 完成 |
| macOS TUN | 完成 |
| Windows TUN | Alpha 动态 Wintun 后端 |
| macOS PID 追踪 | Alpha lsof/ps 后端 |
| TGP X25519 握手和 AEAD | 完成 |
| 多路径 transport adapter | 完成；接口发现和策略尚未接入 |
| 持久 TGP UDP Relay 会话池 | 完成 |
| Client TUN -> routing -> TGP writeback 测试 | 完成 |

## 开发

本仓库使用 `mise` 管理 Go。

```bash
mise install
mise exec -- go test ./...
mise exec -- go build ./...
mise exec -- go run ./cmd/tachyon-core generate-config --mode client > client.json
```

部署 VPS 前，可以先运行本地 TGP relay smoke：

```bash
bash scripts/smoke-tgp-relay.sh
```

它只使用临时 `127.0.0.1` UDP 端口，验证 PSK 握手、UDP echo-like relay 和
`allowed_targets` fail-closed 行为；不会启动 TUN，也不会修改路由、防火墙、
systemd、Docker 或系统代理状态。

## 服务端部署

```bash
sudo bash scripts/install-server.sh --port 443 \
  --allow-target 'cidr=198.51.100.0/24,ports=27015-27050'

sudo TACHYON_ALLOWED_TARGETS='domain=game.example.com,ports=27015' \
  bash scripts/install-server-docker.sh --port 443
```

两种安装脚本都会从 `EarendelArc/tachyon-core` GitHub Releases 下载匹配的
Linux ZIP 资产。`--version latest` 会选择最新 release 条目，包括 alpha
预览版；如需可复现部署，可传入明确 tag，例如
`--version v0.1.0-alpha.13`。Docker 部署会把下载得到的静态
`tachyon-core` 二进制挂载进 `debian:bookworm-slim` 容器运行，不依赖 GHCR
镜像。

服务端 Relay 默认采用 fail-closed 安全策略。安装脚本会生成新的
`tgp.auth.psk` 并写入 `server.json`，需要把该 PSK 复制到 Prism 的 Tachyon
服务器配置中。`server.relay.allowed_targets` 是显式 UDP 目标 allow-list；
如果安装时没有提供目标，服务端会以安全 deny-all 模式启动，不会转发游戏 UDP，
需要配置后再测试。脚本和 Core 配置校验都会拒绝 `0.0.0.0/0`、`::/0`
这类全网目标，并要求每条 allow 规则显式填写 `ports` 列表或范围。Relay 路径
迁移/重绑定当前是 fail-closed；后续协议版本会补充 authenticated rebind
控制路径。

部署完成后，可以用只读验收脚本收集诊断信息：

```bash
sudo bash scripts/verify-server.sh
sudo bash scripts/verify-server.sh --mode docker
bash scripts/verify-server.sh --mode config --binary ./tachyon-core --config ./server.json
```

如果需要我们协助排查 VPS Relay，请把完整输出发给我们。验收脚本会隐藏 PSK，
也不会修改防火墙规则，但公开发布前仍应先检查输出。不要公开或粘贴
`tgp.auth.psk`；只需要说明它是否存在、是否不是占位值，并提供
`allowed_targets` 摘要即可。

完整的本地 smoke 和 VPS 验收清单请见
[docs/tgp-server-verification.zh-CN.md](docs/tgp-server-verification.zh-CN.md)。

Prism/Core IPC 设计请见 [docs/ipc-api.md](docs/ipc-api.md) 和 [docs/ipc-api.zh-CN.md](docs/ipc-api.zh-CN.md)。TGP 线缆格式请见 [docs/tgp-spec.md](docs/tgp-spec.md)。Prism 使用的 GitHub Release 资产说明请见 [docs/release.md](docs/release.md)。
