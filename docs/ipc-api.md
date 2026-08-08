# Tachyon Core IPC API Reference

**Version:** v1.1-preview

**Boundary:** Core exposes only UDP game acceleration state and compatibility
controls. Subscription parsing, Xray lifecycle, Xray JSON, TCP proxying, and
node selection belong to Prism. Core does not depend on Xray.

## Authentication and authority

The client-mode HTTP bridge is disabled unless Prism supplies the inherited
anonymous-pipe contract described in [ipc.md](ipc.md). Every non-preflight
request requires the fresh per-process bearer token. The request peer and
`Host` header must match the configured numeric loopback endpoint. Server mode
does not expose this API.

There is no wildcard CORS policy. Browser requests are accepted only when their
exact origin is present in the startup allowlist; `null` and `*` are forbidden.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/health` | Authenticated Core readiness probe |
| `GET` | `/v1/routing/game-profiles` | Compatibility: list in-memory game profiles |
| `POST` | `/v1/routing/game-profiles` | Compatibility: add an in-memory game profile |
| `PUT` | `/v1/routing/game-profiles/{id}` | Compatibility: replace an in-memory game profile |
| `DELETE` | `/v1/routing/game-profiles/{id}` | Compatibility: remove an in-memory game profile |
| `GET` | `/v1/launchers/steam/scan?root=...` | Compatibility: legacy Steam scan |
| `GET` | `/v1/telemetry/sse` | Authenticated real-time telemetry stream |

Write bodies use JSON, are limited to 64 KiB, reject unknown fields, and reject
multiple JSON values. The SSE connection carries only Core-owned events:
`hello`, `telemetry`, `route_event`, `tgp_session`, and `error`.

## Route decisions

| Action | Meaning |
| --- | --- |
| `tgp` | Encapsulate UDP game traffic into TGP |
| `direct` | Bypass Core handling |
| `drop` | Drop the packet |

There is no `xray` action in Core.

## HTTP status codes

| Status | Meaning |
| --- | --- |
| `400` | Invalid preflight or malformed JSON |
| `401` | Missing or invalid bearer token |
| `403` | Origin is not in the exact allowlist |
| `405` | Method is not supported by the endpoint |
| `413` | Request body exceeds 64 KiB |
| `415` | JSON write has the wrong content type |
| `421` | Peer or Host is not the configured loopback authority |
