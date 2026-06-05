# Tachyon Core

[English](README.md)

Tachyon Core 是 Tachyon 的无头 UDP 游戏加速守护进程。它采用一个二进制文件、
两种运行模式和显式 JSON 配置。

```bash
tachyon-core run --config client.json
tachyon-core run --config server.json
```

## 边界划分

- Prism 负责订阅获取、订阅解析、节点选择、Xray 生命周期、Xray JSON 生成和桌面端
  总控编排。
- Core 只负责 UDP 游戏加速路径：流量接管、基于进程的游戏路由、TGP 传输和服务端
  TGP Relay 行为。
- Tachyon Core 内部不再有 Xray 的运行时或编译期依赖。
- TCP 代理流量属于 Prism/Xray，UDP 游戏流量属于 Tachyon Core/TGP。
- JSON 是 Core 的标准配置格式。早期 YAML 文件仅作为开发兼容格式保留。
- Core JSON 中的相对文件路径会以当前加载的配置文件所在目录为基准解析。

## 架构

```text
客户端模式
  TUN 虚拟网卡 -> PID 追踪器 -> 路由引擎
    UDP 游戏流量  -> TGP 客户端会话
    TCP/代理流量  -> Core 忽略，由 Prism/Xray 负责

服务端模式
  UDP 监听 -> TGP Relay -> 真实游戏服务器
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
sudo bash scripts/install-server.sh --port 443

sudo bash scripts/install-server-docker.sh --port 443
```

Prism/Core IPC 设计见 [docs/ipc-api.md](docs/ipc-api.md) 和
[docs/ipc-api.zh-CN.md](docs/ipc-api.zh-CN.md)，TGP 协议格式见
[docs/tgp-spec.md](docs/tgp-spec.md)。
