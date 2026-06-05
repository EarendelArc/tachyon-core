# Tachyon Core IPC API 参考

**版本：** v1.0-draft

**边界：** Tachyon Core 只暴露 UDP 游戏加速控制与遥测。订阅解析、Xray 生命周期、Xray JSON 生成、TCP 代理编排、持久化游戏配置和启动器扫描都属于 Tachyon Prism。Prism 生成的游戏配置通过 `client.json` 中的 `client.routing.game_profiles` 传给 Core。

## HTTP Bridge

当前实现会在 `127.0.0.1:55123` 暴露本地 HTTP JSON bridge。路由配置变更接口仅作为兼容层保留；新的 Prism 会在本地持久化 profiles，并重新生成 Core JSON。

| Method | Path | 用途 |
| --- | --- | --- |
| `GET` | `/v1/health` | Core 就绪探测 |
| `GET` | `/v1/routing/game-profiles` | 兼容：列出内存中的游戏配置 |
| `POST` | `/v1/routing/game-profiles` | 兼容：添加内存游戏配置 |
| `PUT` | `/v1/routing/game-profiles/{id}` | 兼容：替换内存游戏配置 |
| `DELETE` | `/v1/routing/game-profiles/{id}` | 兼容：删除内存游戏配置 |
| `GET` | `/v1/launchers/steam/scan?root=...` | 兼容：旧 Steam 扫描入口 |

## 路由决策

Core 的路由动作被刻意限制为：

| Action | 含义 |
| --- | --- |
| `tgp` | 把 UDP 游戏流量封装进 TGP |
| `direct` | Core 不处理该流量 |
| `drop` | 丢弃数据包 |

Core 中没有 `xray` action。任何 Xray 进程、TCP 代理以及订阅出站节点选择都由 Prism 负责。

## 未来遥测事件

计划中的 WebSocket 遥测流只包含 Core 自己拥有的状态：

| Event | 方向 | 描述 |
| --- | --- | --- |
| `hello` | Core -> Prism | Core 版本、平台、配置路径 |
| `telemetry` | Core -> Prism | 包计数、TGP 会话指标、资源占用 |
| `route_event` | Core -> Prism | 某条流的游戏路由决策 |
| `tgp_session` | Core -> Prism | TGP 会话打开、关闭或迁移 |
| `error` | Core -> Prism | 非致命 Core 错误 |

示例路由事件：

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

| Code | 含义 |
| --- | --- |
| `CORE_NOT_READY` | Core 尚未初始化完成 |
| `INVALID_CONFIG` | Core JSON 配置校验失败 |
| `TUN_PERMISSION_DENIED` | 操作系统权限不足，无法创建 TUN 设备 |
| `TGP_SESSION_FAILED` | TGP 会话握手或传输失败 |
