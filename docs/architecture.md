# Tachyon Core Architecture

[中文说明](architecture.zh-CN.md)

Core has four major boundaries:

1. TUN stack: captures packets and reconstructs flow metadata.
2. PID tracking: maps flows to process metadata.
3. Routing engine: decides TGP, direct, or drop for game-related flows.
4. TGP transport: carries selected UDP game packets to the relay.

The current Core-only minimum architecture is selective capture, not a full
default-route network stack:

```text
explicit destination CIDRs -> Core TUN -> PID/rule decision -> TGP or fail closed
all other destinations     -> native OS path (never enters Core TUN)
```

Core does not yet implement native direct forwarding or DNS forwarding.
Therefore `auto_route=true`, `dns_hijack=true`, and `tgp_only=false` are invalid
client configurations. Windows installs only `client.tun.game_routes` in a
transaction and removes them on initialization failure or shutdown. Linux and
macOS reject non-empty `game_routes` before TUN creation until their route
transactions have equivalent safety. A direct decision for a packet that
nevertheless enters the TUN is a fatal fail-closed error.

An OS destination route cannot identify the originating process. If a game and
a non-game process contact the same configured CIDR, both packets enter Core;
the PID/rule engine can reject the non-game packet, but cannot send it back to
the native route. Prism must therefore use the narrowest known game-server
CIDRs and must not describe this mode as true process-isolated routing.

Before any route mutation, Core resolves all current Relay A/AAAA addresses and
rejects a route that contains one. The TGP manager validates the actual resolved
endpoint again before every session dial, so a later DNS change cannot recurse
the Relay transport into its own TUN.

Game routing priority:

```text
manual profile > launcher child process > known game profile > process/CIDR/protocol rule > default
```

TGP receives only traffic that the routing engine has classified as game UDP. It does not know whether the decision came from a manual rule, Steam, or a future launcher provider. Xray and TCP proxy orchestration are intentionally outside Core and belong to Prism.

Generic `domain` and `geoip` client route rules are rejected during config
validation until deterministic matchers exist. TGP UDP writeback supports both
IPv4 and IPv6 packets. Windows route installation supports both address
families; real elevated-host validation remains required.

Prism-managed game profiles are embedded in Core JSON under `client.routing.game_profiles`. Launcher heuristics live under `client.routing.launchers`. The legacy local HTTP routing bridge is kept only as an integration compatibility surface; a Prism-generated `client.json` is enough to start Core with the intended game routing policy.

## Telemetry Stream

Core exposes a real-time Server-Sent Events (SSE) endpoint at `GET /v1/telemetry/sse` on the same HTTP bridge used for IPC. No external dependencies are required; the `internal/observability` package implements the broadcaster using only the Go standard library.

**Event types:**

| Event | Description |
| --- | --- |
| `hello` | Sent once on connect: Core version, platform, config path |
| `telemetry` | Periodic snapshot: packet counters, TGP sessions, goroutine count |
| `route_event` | Fired per packet: process name, flow 4-tuple, decision, matched rule |
| `tgp_session` | TGP session lifecycle: opened, closed, migrated |
| `error` | Non-fatal Core error |

**Data flow:**

```text
pipeline.handlePacket()
  ├─ router.Decide() -> onDecision callback -> broadcaster.Broadcast(route_event)
  ├─ pipeline.Snapshot() <- collector.Snapshot() -> broadcaster(telemetry, periodic)
  └─ tgpManager.ActiveSessions() <- collector.Snapshot()
```

The broadcast interval is controlled by `ipc.telemetry_interval_ms` (default 500ms). Slow clients have events dropped rather than blocking the packet pipeline.
