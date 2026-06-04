# Tachyon Core IPC Draft

[中文说明](ipc.zh-CN.md)

Prism controls Core through a local gRPC or WebSocket API. The first stable API
surface is routing profile management.

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

Manual game profiles must be preserved exactly as entered by the user. Automatic
scans may add suggestions, but they must not override manual routing choices.

## HTTP Bridge

The first implementation exposes a small local HTTP JSON bridge on
`127.0.0.1:55123`:

- `GET /v1/health`
- `GET /v1/routing/game-profiles`
- `POST /v1/routing/game-profiles`
- `PUT /v1/routing/game-profiles/{id}`
- `DELETE /v1/routing/game-profiles/{id}`

This bridge is a compatibility layer for early Prism integration. The routing
service behind it is transport-agnostic and can be reused by gRPC or WebSocket
handlers.
