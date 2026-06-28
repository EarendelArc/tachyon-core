# Tachyon Core 架构

[English](architecture.md)

Core 有四个主要边界：

1. TUN 栈：接管数据包并还原流元数据。
2. PID 追踪：把网络流映射到进程元数据。
3. 路由引擎：对游戏相关流量决定 TGP、直连或丢弃。
4. TGP 传输：把选中的 UDP 游戏包送到 Relay。

游戏路由优先级：

```text
手动配置 > 启动器子进程 > 已知游戏配置 > 进程/Geo 规则 > 默认策略
```

TGP 只接收已经被路由引擎判定为游戏 UDP 的流量。它不关心该决策来自手动规则、Steam，还是未来的其他启动器 provider。Xray 与 TCP 代理编排被刻意排除在 Core 之外，由 Prism 负责。

Prism 管理的游戏配置会嵌入 Core JSON 的 `client.routing.game_profiles`。启动器启发式策略位于 `client.routing.launchers`。旧的本地 HTTP 路由桥仅作为集成兼容面保留；Prism 生成的 `client.json` 已足够按预期游戏路由策略启动 Core。

## 遥测流

Core 在 IPC 使用的同一个 HTTP bridge 上暴露实时 Server-Sent Events (SSE) 端点：`GET /v1/telemetry/sse`。它不需要外部依赖；`internal/observability` 包只使用 Go 标准库实现 broadcaster。

**事件类型：**

| 事件 | 说明 |
| --- | --- |
| `hello` | 连接后立即发送一次：Core 版本、平台、配置路径 |
| `telemetry` | 周期快照：包计数、TGP 会话、goroutine 数量 |
| `route_event` | 每个数据包触发：进程名、流四元组、决策、命中规则 |
| `tgp_session` | TGP 会话生命周期：打开、关闭、迁移 |
| `error` | 非致命 Core 错误 |

**数据流：**

```text
pipeline.handlePacket()
  ├─ router.Decide() -> onDecision callback -> broadcaster.Broadcast(route_event)
  ├─ pipeline.Snapshot() <- collector.Snapshot() -> broadcaster(telemetry, periodic)
  └─ tgpManager.ActiveSessions() <- collector.Snapshot()
```

广播间隔由 `ipc.telemetry_interval_ms` 控制，默认 500ms。慢客户端会丢弃事件，而不是阻塞数据包管道。