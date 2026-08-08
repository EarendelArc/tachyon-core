# Tachyon Core IPC Preview

[中文说明](ipc.zh-CN.md)

Prism controls Core through a local HTTP compatibility bridge for health,
route telemetry, and TGP session telemetry. Persistent game profiles,
subscriptions, Xray configuration, and Xray lifecycle remain Prism-owned.
Core has no runtime or build-time Xray dependency.

## Security boundary

The bridge exists only in `client` mode and is disabled by default. Server mode
never starts this GUI control surface. Before launching Core, Prism must create
an anonymous pipe, retain its read end, make only the child write handle
inheritable, and put the numeric child handle in
`TACHYON_IPC_TOKEN_HANDLE`. Core generates a fresh 256-bit session token,
writes it once to that pipe, closes the handle, and clears the environment
variable. The token is never accepted through argv or an environment variable
and must never be logged.

If the inherited pipe is missing or invalid, Core continues its client data
plane without opening an HTTP listener. This is intentionally fail-closed while
Prism completes the inherited-handle integration.

The listener accepts only the exact numeric hosts `127.0.0.1` and `::1`.
Hostnames, wildcard addresses, other members of `127.0.0.0/8`, non-loopback
addresses, mismatched `Host` authorities, and non-loopback peers are rejected.
Every endpoint, including health and telemetry, requires
`Authorization: Bearer <session-token>`.

Browser CORS is disabled by default. A native WebView integration may provide
an exact comma-separated allowlist through `TACHYON_IPC_ALLOWED_ORIGINS`.
`null`, `*`, partial origins, userinfo, queries, fragments, and unlisted origins
are rejected. Preflight responses are emitted only for an exact allowed origin
and a supported method.

## HTTP limits

- JSON writes require `Content-Type: application/json`.
- Request bodies are limited to 64 KiB and must contain one JSON value.
- Headers are limited to 16 KiB.
- Read, header-read, write, and idle deadlines are configured by Core.
- Responses use explicit JSON or SSE content types and `nosniff`/`no-store`
  security headers.

## Compatibility endpoints

- `GET /v1/health`
- `GET /v1/routing/game-profiles`
- `POST /v1/routing/game-profiles`
- `PUT /v1/routing/game-profiles/{id}`
- `DELETE /v1/routing/game-profiles/{id}`
- `GET /v1/launchers/steam/scan`
- `GET /v1/telemetry/sse`

The routing endpoints are compatibility-only. New Prism builds own persistence
and regenerate `client.json`.

For manual diagnostics, `tachyonctl health` reads the token only from standard
input:

```bash
tachyonctl health --addr 127.0.0.1:55123 --token-stdin
```

The caller must obtain the token from the parent side of the inherited pipe;
do not paste it into argv, environment variables, shell history, or logs.
