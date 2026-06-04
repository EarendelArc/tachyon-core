# Tachyon Core IPC 草案

[English](ipc.md)

Prism 通过本地 gRPC 或 WebSocket API 控制 Core。第一批稳定 API 聚焦于路由配置管理。

```protobuf
service RoutingService {
  rpc ListGameProfiles(ListGameProfilesRequest) returns (ListGameProfilesResponse);
  rpc AddGameProfile(AddGameProfileRequest) returns (GameProfile);
  rpc UpdateGameProfile(UpdateGameProfileRequest) returns (GameProfile);
  rpc RemoveGameProfile(RemoveGameProfileRequest) returns (RemoveGameProfileResponse);
  rpc ScanInstalledGames(ScanInstalledGamesRequest) returns (ScanInstalledGamesResponse);
  rpc SetProgramGameMode(SetProgramGameModeRequest) returns (SetProgramGameModeResponse);
}
```

用户手动添加的游戏配置必须严格保留。自动扫描可以产生建议，但不能覆盖用户手动设置的路由选择。

## HTTP Bridge

第一版实现会在 `127.0.0.1:55123` 暴露一个很小的本地 HTTP JSON bridge：

- `GET /v1/health`
- `GET /v1/routing/game-profiles`
- `POST /v1/routing/game-profiles`
- `PUT /v1/routing/game-profiles/{id}`
- `DELETE /v1/routing/game-profiles/{id}`

这个 bridge 用于早期 Prism 集成。它背后的 routing service 与传输层解耦，后续可以直接复用于 gRPC 或 WebSocket handler。
