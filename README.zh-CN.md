# Tachyon Core

[English](README.md)

Tachyon Core 是 Tachyon 的无头核心守护进程。

它负责数据包接管、基于进程的智能路由、Xray 生命周期管理，以及面向游戏 UDP 流量的 Tachyon Game Protocol 客户端路径。

## 架构规则

- Prism 只能通过 IPC 与 Core 通信。
- Xray 作为外部托管二进制运行，绝不编译进 Core。
- TCP 代理流量与游戏 UDP 流量走完全分离的传输路径。
- 手动游戏配置的优先级高于自动识别。
- 平台相关能力必须收敛在小而清晰的接口后面。

## 第一阶段里程碑

1. 跑通 mock TUN 流水线，并基于进程元数据做路由决策。
2. 通过 `ProxyRunner` 管理 Xray 子进程。
3. 实现带 pacing 指标的 TGP loopback UDP 会话。
4. 为 Windows、macOS、Linux 增加 PID tracking provider。

## 开发环境

本仓库使用 `mise` 管理工具版本。

```bash
mise install
go test ./...
```

锁定的 Go 版本声明在 `.tool-versions` 中。
