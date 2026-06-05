# Tachyon Core IPC Draft

[中文说明](ipc.zh-CN.md)

Prism controls Core through local IPC for health, lifecycle, route telemetry,
and TGP session telemetry. Persistent game profile management belongs to Prism.
Prism writes profiles into Core JSON under `client.routing.game_profiles`.

```protobuf
service CoreControl {
  rpc GetStatus(StatusRequest) returns (StatusResponse);
  rpc StreamTelemetry(TelemetryRequest) returns (stream TelemetryEvent);
}
```

Manual game profiles must be preserved exactly as entered by the user. Automatic
launcher scans may add suggestions in Prism, but they must not override manual
routing choices. Core consumes the resulting JSON and makes runtime decisions.

## HTTP Bridge

The current implementation exposes a small local HTTP JSON bridge on
`127.0.0.1:55123`:

- `GET /v1/health`
- `GET /v1/routing/game-profiles`
- `POST /v1/routing/game-profiles`
- `PUT /v1/routing/game-profiles/{id}`
- `DELETE /v1/routing/game-profiles/{id}`

The routing endpoints are compatibility-only for early Prism integration. New
Prism builds own persistence locally and regenerate `client.json` instead.
