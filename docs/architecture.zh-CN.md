# Tachyon Core 架构

[English](architecture.md)

Windows 选择性路由以 Wintun adapter LUID、interface index、目标、next hop、metric 和 protocol 作为精确身份，因此接口重命名不影响 ownership。每次 Add 前记录 baseline，Add 后无论成功、超时或取消都读回；每条删除使用独立超时，失败项保留给后续 `Close` 重试。进程崩溃后的 journal 只 reconcile 同一稳定 Wintun 身份上曾确认由 Tachyon 创建且属性完全匹配的路由。

Core 在 TUN 创建和路由修改前一次解析 Relay 并 pin 获批的 `IP:port` 集合。拨号、重连和 remote 迁移均复用同一 validator，安装路由后不再依赖系统 DNS。空 `game_routes` 仅表示无额外游戏目标路由；Windows 仍以 `store=active` 配置 TUN 地址和 MTU。

## 选择性路由边界

Windows 仅事务性安装 `client.tun.game_routes` 中显式列出的 IPv4/IPv6 目标路由，并在初始化失败、超时取消和正常停止时逆序删除。`0.0.0.0/0`、`::/0` 以及覆盖任一 Relay 解析地址的 CIDR 会被 fail-closed 拒绝。Linux 与 macOS 当前在创建 TUN 之前拒绝非空 `game_routes`，不会退化为全局 `auto_route`。

操作系统目标路由无法区分进程。如果游戏与非游戏程序访问同一目标 CIDR，两者都会进入 Core；PID/规则引擎只能在接管后决定是否送入 TGP，不能把非游戏包重新注入原生路径。因此这不是严格的按进程隔离，Prism 必须生成尽可能窄的目标 CIDR。

Core 在 TUN 和路由变更前一次解析 Relay 当前全部 A/AAAA 地址，并 pin 获批的 endpoint 集合。每次 TGP 会话拨号、重连和迁移都复用同一 validator；任何 endpoint 落入游戏 CIDR 或不在批准集合中都会失败，且不会在路由安装后重新查询系统 DNS。

Core 有四个主要边界：

1. TUN 栈：接管数据包并还原流元数据。
2. PID 追踪：把网络流映射到进程元数据。
3. 路由引擎：对游戏相关流量决定 TGP、直连或丢弃。
4. TGP 传输：把选中的 UDP 游戏包送到 Relay。

当前 Core-only 的最小架构是选择性接管，而不是完整的默认路由网络栈：

```text
OS 目标/进程策略 -> 选中的游戏 UDP -> Core TUN -> TGP
其他所有流量    -> OS 原生路径（不得进入 Core TUN）
```

Core 尚未实现原生 direct 转发和 DNS 转发。因此 `auto_route=true`、
`dns_hijack=true`、`tgp_only=false` 都是无效客户端配置。若 direct 决策的数据包仍然
进入 TUN，pipeline 会以致命错误 fail-closed，而不是只记录日志后吞包。

游戏路由优先级：

```text
手动配置 > 启动器子进程 > 已知游戏配置 > 进程/CIDR/协议规则 > 默认策略
```

TGP 只接收已经被路由引擎判定为游戏 UDP 的流量。它不关心该决策来自手动规则、Steam，还是未来的其他启动器 provider。Xray 与 TCP 代理编排被刻意排除在 Core 之外，由 Prism 负责。

通用客户端 `domain`、`geoip` 规则在具备确定性 matcher 前会在配置阶段被拒绝。TGP
UDP 回包已经支持 IPv4 和 IPv6；OS 级路由安装不属于 packet builder，仍需按平台验证。

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
