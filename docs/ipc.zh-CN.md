# Tachyon Core IPC 草案

[English](ipc.md)

Prism 通过本地 IPC 控制 Core 的健康状态、生命周期、路由遥测和 TGP 会话遥测。持久化游戏配置管理属于 Prism。Prism 会把 profiles 写入 Core JSON 的 `client.routing.game_profiles`。

```protobuf
service CoreControl {
  rpc GetStatus(StatusRequest) returns (StatusResponse);
  rpc StreamTelemetry(TelemetryRequest) returns (stream TelemetryEvent);
}
```

用户手动添加的游戏配置必须严格保留。自动启动器扫描可以在 Prism 中产生建议，但不能覆盖用户手动设置的路由选择。Core 消费最终 JSON 并在运行时做决策。

## HTTP Bridge

当前实现会在 `127.0.0.1:55123` 暴露一个很小的本地 HTTP JSON bridge：

- `GET /v1/health`
- `GET /v1/routing/game-profiles`
- `POST /v1/routing/game-profiles`
- `PUT /v1/routing/game-profiles/{id}`
- `DELETE /v1/routing/game-profiles/{id}`

这些 routing endpoints 仅作为早期 Prism 集成兼容层保留。新的 Prism 会在本地持久化配置，并重新生成 `client.json`。
