# Tachyon Core IPC API Reference

**Version:** v1.0-draft

**Boundary:** Tachyon Core exposes only UDP game acceleration controls and
telemetry. Subscription parsing, Xray lifecycle, Xray JSON generation, and TCP
proxy orchestration belong to Tachyon Prism. Prism also owns persistent game
profiles and launcher scanning; generated profiles are passed to Core through
`client.routing.game_profiles` in `client.json`.

## HTTP Bridge

The current implementation exposes a local HTTP JSON bridge on
`127.0.0.1:55123`. Routing profile mutation endpoints are compatibility-only;
new Prism builds persist profiles locally and regenerate Core JSON instead.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/health` | Core readiness probe |
| `GET` | `/v1/routing/game-profiles` | Compatibility: list in-memory game profiles |
| `POST` | `/v1/routing/game-profiles` | Compatibility: add an in-memory game profile |
| `PUT` | `/v1/routing/game-profiles/{id}` | Compatibility: replace an in-memory game profile |
| `DELETE` | `/v1/routing/game-profiles/{id}` | Compatibility: remove an in-memory game profile |
| `GET` | `/v1/launchers/steam/scan?root=...` | Compatibility: legacy Steam scan endpoint |
| `GET` | `/v1/telemetry/sse` | Real-time telemetry stream (SSE) |

## Route Decisions

Core route actions are intentionally limited:

| Action | Meaning |
| --- | --- |
| `tgp` | Encapsulate UDP game traffic into TGP |
| `direct` | Bypass Core handling |
| `drop` | Drop the packet |

There is no `xray` action in Core. Prism is responsible for any Xray process,
TCP proxy, and subscription-derived outbound selection.

## Telemetry Stream (SSE)

The telemetry stream is implemented as Server-Sent Events (SSE) at
`/v1/telemetry/sse`. Clients connect with a standard HTTP GET request and
receive a continuous stream of `text/event-stream` data. A `hello` event is
sent immediately on connect, followed by periodic `telemetry` snapshots at
the interval configured in `ipc.telemetry_interval_ms` (default 500ms).

The stream only includes Core-owned state:

| Event | Direction | Description |
| --- | --- | --- |
| `hello` | Core -> Prism | Core version, platform, config path |
| `telemetry` | Core -> Prism | Packet counters, TGP session metrics, resource usage |
| `route_event` | Core -> Prism | Game routing decision for a flow |
| `tgp_session` | Core -> Prism | TGP session opened, closed, or migrated |
| `error` | Core -> Prism | Non-fatal Core error |

Example route event:

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

## Future gRPC Shape

```protobuf
syntax = "proto3";
package tachyon.core.v1;

service CoreControl {
  rpc GetStatus(StatusRequest) returns (StatusResponse);
  rpc StreamTelemetry(TelemetryRequest) returns (stream TelemetryEvent);
}
```

## Error Codes

| Code | Meaning |
| --- | --- |
| `CORE_NOT_READY` | Core has not finished initialising |
| `INVALID_CONFIG` | Core JSON config failed validation |
| `INVALID_PROFILE` | Game profile payload is invalid |
| `TUN_PERMISSION_DENIED` | Insufficient OS privileges to create TUN device |
| `TGP_SESSION_FAILED` | TGP session handshake or transport failed |

