# Tachyon Core IPC API 参考

**版本：** v1.0-draft

**边界：** Tachyon Core 只暴露 UDP 游戏加速控制与遥测。订阅解析、Xray 生命周期、Xray JSON 生成和 TCP 代理编排都属于 Tachyon Prism。Prism 也负责持久化游戏配置和启动器扫描；生成后的配置会通过 `client.json` 的 `client.routing.game_profiles` 传给 Core。

## HTTP Bridge

当前实现会在 `127.0.0.1:55123` 暴露本地 HTTP JSON bridge。路由配置变更端点仅用于兼容；新的 Prism 会在本地持久化配置，并重新生成 Core JSON。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/v1/health` | Core 就绪探针 |
| `GET` | `/v1/routing/game-profiles` | 兼容：列出内存中的游戏配置 |
| `POST` | `/v1/routing/game-profiles` | 兼容：添加内存中的游戏配置 |
| `PUT` | `/v1/routing/game-profiles/{id}` | 兼容：替换内存中的游戏配置 |
| `DELETE` | `/v1/routing/game-profiles/{id}` | 兼容：移除内存中的游戏配置 |
| `GET` | `/v1/launchers/steam/scan?root=...` | 兼容：旧 Steam 扫描端点 |
| `GET` | `/v1/telemetry/sse` | 实时遥测流 (SSE) |

## 路由决策

Core 的路由动作被刻意限制：

| 动作 | 含义 |
| --- | --- |
| `tgp` | 将 UDP 游戏流量封装进 TGP |
| `direct` | 绕过 Core 处理 |
| `drop` | 丢弃数据包 |

Core 中没有 `xray` 动作。任何 Xray 进程、TCP 代理以及由订阅得到的出站节点选择都由 Prism 负责。

## 遥测流 (SSE)

遥测流以 Server-Sent Events (SSE) 形式在 `/v1/telemetry/sse` 实现。客户端通过标准 HTTP GET 请求连接，并持续接收 `text/event-stream` 数据。连接后会立即发送 `hello` 事件，随后按 `ipc.telemetry_interval_ms` 配置的间隔发送周期性 `telemetry` 快照，默认 500ms。

该流只包含 Core 自身拥有的状态：

| 事件 | 方向 | 说明 |
| --- | --- | --- |
| `hello` | Core -> Prism | Core 版本、平台、配置路径 |
| `telemetry` | Core -> Prism | 包计数、TGP 会话指标、资源使用 |
| `route_event` | Core -> Prism | 某个流的游戏路由决策 |
| `tgp_session` | Core -> Prism | TGP 会话打开、关闭或迁移 |
| `error` | Core -> Prism | 非致命 Core 错误 |

路由事件示例：

```json
{
  "type": "route_event",
  "seq": 100,
  "ts": "2026-01-01T00:00:01.000Z",
  "data": {
    "process_name": "cs2.exe",
    "pid": 9832,
    "src": "198.18.0.2:57392",
    "dst": "162.254.195.4:27015",
    "proto": "udp",
    "decision": "tgp",
    "rule_matched": "process:cs2.exe"
  }
}
```

## 未来 gRPC 形态

```protobuf
syntax = "proto3";
package tachyon.core.v1;

service CoreControl {
  rpc GetStatus(StatusRequest) returns (StatusResponse);
  rpc StreamTelemetry(TelemetryRequest) returns (stream TelemetryEvent);
}
```

## 错误码

| 代码 | 含义 |
| --- | --- |
| `CORE_NOT_READY` | Core 还没有完成初始化 |
| `INVALID_CONFIG` | Core JSON 配置验证失败 |
| `INVALID_PROFILE` | 游戏配置 payload 无效 |
| `TUN_PERMISSION_DENIED` | 操作系统权限不足，无法创建 TUN 设备 |
| `TGP_SESSION_FAILED` | TGP 会话握手或传输失败 |