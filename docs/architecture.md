# Tachyon Core Architecture

[ä¸­æ–‡è¯´æ˜Ž](architecture.zh-CN.md)

Core has four major boundaries:

1. TUN stack: captures packets and reconstructs flow metadata.
2. PID tracking: maps flows to process metadata.
3. Routing engine: decides TGP, direct, or drop for game-related flows.
4. TGP transport: carries selected UDP game packets to the relay.

Game routing priority:

```text
manual profile > launcher child process > known game profile > process/geo rule > default
```

TGP receives only traffic that the routing engine has classified as game UDP.
It does not know whether the decision came from a manual rule, Steam, or a
future launcher provider. Xray and TCP proxy orchestration are intentionally
outside Core and belong to Prism.

Prism-managed game profiles are embedded in Core JSON under
`client.routing.game_profiles`. Launcher heuristics live under
`client.routing.launchers`. The legacy local HTTP routing bridge is kept only as
an integration compatibility surface; a Prism-generated `client.json` is enough
to start Core with the intended game routing policy.

## Telemetry Stream

Core exposes a real-time Server-Sent Events (SSE) endpoint at
GET /v1/telemetry/sse on the same HTTP bridge used for IPC. No external
dependencies are required ¡ª the internal/observability package implements
the broadcaster using only the Go standard library.

**Event types:**

| Event | Description |
| --- | --- |
| hello | Sent once on connect: Core version, platform, config path |
| 	elemetry | Periodic snapshot: packet counters, TGP sessions, goroutine count |
| oute_event | Fired per packet: process name, flow 4-tuple, decision, matched rule |
| 	gp_session | TGP session lifecycle: opened, closed, migrated |
| error | Non-fatal Core error |

**Data flow:**

`	ext
pipeline.handlePacket()
  ©À©¤ router.Decide() ¡ú onDecision callback ¡ú broadcaster.Broadcast(route_event)
  ©À©¤ pipeline.Snapshot() ¡û collector.Snapshot() ¡ú broadcaster(telemetry, periodic)
  ©¸©¤ tgpManager.ActiveSessions() ¡û collector.Snapshot()
`

The broadcast interval is controlled by ipc.telemetry_interval_ms (default 500ms).
Slow clients have events dropped rather than blocking the pipeline.
