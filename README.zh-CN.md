# Tachyon Core

[English](README.md)

Tachyon Core 是 Tachyon 的无头网络核心守护进程。它采用类似 xray-core 的
运行模型：一个二进制文件、两种运行模式、显式 JSON 配置。

```bash
tachyon-core run --config client.json
tachyon-core run --config server.json
```

## 边界划分

- Prism 负责订阅获取、订阅解析、节点选择，以及后续生成 Core/Xray 可消费的
  配置。
- Core 负责流量接管、基于进程的路由、Xray 子进程生命周期、TGP 传输和服务端
  Relay 行为。
- Xray-core 永远不会被编译进 Core，只会作为外部二进制被下载、校验和启动。
- TCP 代理流量与 UDP 游戏流量端到端走完全独立的传输路径。
- JSON 是 Core 的标准配置格式。早期 YAML 文件仅作为开发兼容格式保留。
- Core JSON 中的相对文件路径会以当前加载的配置文件所在目录为基准解析，包括
  `xray.config_file`。

## 架构

```text
客户端模式
  TUN 虚拟网卡 -> PID 追踪器 -> 路由引擎
    TCP 网页流量  -> 本地 Xray 子进程
    UDP 游戏流量  -> TGP 客户端会话

服务端模式
  :443 TCP/UDP 监听
    TLS ClientHello -> 本地 Xray 后端
    TGP/DTLS 包     -> TGP Relay
```

## 当前进度

| 模块 | 状态 |
| --- | --- |
| 客户端/服务端统一 CLI | 已完成 |
| JSON 配置读取与生成 | 已完成 |
| 基于进程的游戏路由配置 | 已完成 |
| 手动游戏模式配置 API | 已完成 |
| Steam 游戏库扫描 API | 已完成 |
| Linux TUN 与 PID 追踪 | 已完成 |
| Windows PID 追踪 | 已完成 |
| macOS TUN | 已完成 |
| Windows TUN | 存根 |
| macOS PID 追踪 | 存根 |
| Xray 子进程 Runner | 已完成 |
| Xray 客户端配置生成 | 已完成 |
| TGP X25519 握手与 AEAD | 已完成 |
| TGP UDP Relay 骨架 | 已完成 |
| 客户端 TUN -> 路由 -> TGP 回写测试 | 已完成 |

## 开发

本仓库使用 `mise` 管理 Go 版本。

```bash
mise install
mise exec -- go test ./...
mise exec -- go build ./...
mise exec -- go run ./cmd/tachyon-core generate-config --mode client > client.json
```

## 服务端部署

```bash
sudo bash scripts/install-server.sh \
  --domain vpn.example.com \
  --email admin@example.com

sudo bash scripts/install-server-docker.sh \
  --domain vpn.example.com \
  --email admin@example.com
```

Prism/Core IPC 设计见 [docs/ipc-api.md](docs/ipc-api.md)，TGP 协议格式见
[docs/tgp-spec.md](docs/tgp-spec.md)。
