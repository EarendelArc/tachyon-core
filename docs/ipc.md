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
