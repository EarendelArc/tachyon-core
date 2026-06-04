# Tachyon Prism ↔ Core IPC API Reference

**Version:** v1.0-draft

**Transport:** WebSocket (real-time telemetry) + gRPC (control plane)

**Core listens on:** `127.0.0.1:9999` (WebSocket) | `127.0.0.1:50051` (gRPC)

---

## Overview

Tachyon Prism communicates with Tachyon Core exclusively through two IPC channels:

```
Prism (UI)
│
├─── WebSocket ws://127.0.0.1:9999/ws
│         Real-time, server-push telemetry stream (Core → Prism)
│         JSON framing, one event object per message
│
└─── gRPC grpc://127.0.0.1:50051
          Request/response control commands (Prism → Core)
          Protobuf encoding, TLS optional (loopback only)
```

---

## 1. WebSocket Telemetry Stream

### Connection

```
ws://127.0.0.1:9999/ws
```

No authentication required (loopback-only). Core sends a `hello` event
immediately on connection, then emits `telemetry` events on a configurable
interval (default 500 ms).

### Event Envelope

Every message is a JSON object with a top-level `type` field:

```jsonc
{
  "type": "<event_type>",     // string, see table below
  "seq":  12345,              // monotonically increasing per connection
  "ts":   "2026-01-01T00:00:00.123Z",  // ISO 8601 UTC
  "data": { ... }             // event-specific payload
}
```

### Event Types

| `type` | Direction | Description |
|---|---|---|
| `hello` | Core → Prism | Sent once on connection; contains Core version info |
| `telemetry` | Core → Prism | Periodic network metrics snapshot |
| `route_event` | Core → Prism | A routing decision was made for a process |
| `xray_status` | Core → Prism | Xray runner state changed |
| `tgp_session` | Core → Prism | TGP session opened / closed / migrated |
| `xray_download_progress` | Core → Prism | Streaming download progress |
| `error` | Core → Prism | Non-fatal error notification |

---

### `hello`

```jsonc
{
  "type": "hello",
  "seq": 0,
  "ts": "2026-01-01T00:00:00.000Z",
  "data": {
    "core_version": "v0.1.0",
    "go_version": "go1.24.0",
    "platform": "windows/amd64",
    "tun_device": "TachyonTUN",
    "xray_installed_version": "v25.5.16",  // null if not installed
    "config_path": "C:\\Users\\user\\AppData\\Roaming\\Tachyon\\config.json"
  }
}
```

---

### `telemetry`

Emitted every `telemetry_interval_ms` milliseconds (default: 500).

```jsonc
{
  "type": "telemetry",
  "seq": 42,
  "ts": "2026-01-01T00:00:00.500Z",
  "data": {
    // TGP session metrics (null when no active TGP session)
    "tgp": {
      "rtt_ms": 12.3,          // smoothed RTT to TGP server
      "jitter_ms": 0.4,        // EWMA jitter (RFC 3550)
      "loss_pct": 0.1,         // packet loss percentage [0, 100]
      "fec_recovered": 3,      // packets recovered via RS-FEC this interval
      "active_sessions": 1,
      "migrations": 0          // connection migrations this session
    },
    // Overall throughput
    "throughput": {
      "tx_bps": 1048576,       // transmit bits per second
      "rx_bps": 2097152,       // receive bits per second
      "tx_packets": 1280,
      "rx_packets": 2560
    },
    // Routing engine decisions in this interval
    "routing": {
      "xray": 142,             // packets routed via Xray
      "tgp": 87,               // packets routed via TGP
      "direct": 12,            // packets passed through unmodified
      "dropped": 0
    },
    // Xray runner state
    "xray_state": "running",   // one of: idle|starting|running|stopping|stopped|failed
    // System resource usage by Core
    "system": {
      "cpu_pct": 1.2,
      "mem_mb": 45.6,
      "goroutines": 48,
      "open_fds": 23
    }
  }
}
```

---

### `route_event`

Emitted each time the routing engine makes a decision for a new flow.

```jsonc
{
  "type": "route_event",
  "seq": 100,
  "ts": "2026-01-01T00:00:01.000Z",
  "data": {
    "process_name": "cs2.exe",
    "pid": 9832,
    "src": "192.168.1.5:57392",
    "dst": "162.254.195.4:27015",
    "proto": "udp",
    "decision": "tgp",          // "xray" | "tgp" | "direct" | "drop"
    "rule_matched": "process:cs2.exe"
  }
}
```

---

### `xray_status`

```jsonc
{
  "type": "xray_status",
  "seq": 7,
  "ts": "2026-01-01T00:00:00.200Z",
  "data": {
    "state": "running",         // RunnerState string
    "version": "v25.5.16",
    "pid": 12840,               // OS PID of the xray process (null if stopped)
    "error": null               // error message string if state == "failed"
  }
}
```

---

### `tgp_session`

```jsonc
{
  "type": "tgp_session",
  "seq": 15,
  "ts": "2026-01-01T00:00:02.000Z",
  "data": {
    "event": "opened",          // "opened" | "closed" | "migrated"
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "remote_addr": "203.0.113.42:443",
    // Only present for "migrated":
    "old_local_addr": null,
    "new_local_addr": null
  }
}
```

---

### `xray_download_progress`

```jsonc
{
  "type": "xray_download_progress",
  "seq": 200,
  "ts": "2026-01-01T00:00:05.000Z",
  "data": {
    "version": "v25.5.16",
    "bytes_received": 8388608,
    "total_bytes": 16777216,
    "pct": 50.0,
    "done": false,
    "error": null
  }
}
```

---

## 2. gRPC Control Plane

### Proto Package

```protobuf
syntax = "proto3";
package tachyon.core.v1;
option go_package = "github.com/tachyon-space/tachyon-core/internal/ipc/proto;ipcpb";
```

### Service Definition

```protobuf
service CoreControl {
  // Proxy management
  rpc StartProxy        (StartProxyRequest)   returns (StartProxyResponse);
  rpc StopProxy         (StopProxyRequest)    returns (StopProxyResponse);
  rpc RestartProxy      (RestartProxyRequest) returns (RestartProxyResponse);
  rpc GetStatus         (StatusRequest)       returns (StatusResponse);

  // Xray binary management
  rpc ListXrayReleases  (ListXrayReleasesRequest) returns (ListXrayReleasesResponse);
  rpc DownloadXray      (DownloadXrayRequest)     returns (stream DownloadXrayProgress);
  rpc RemoveXray        (RemoveXrayRequest)        returns (RemoveXrayResponse);

  // Routing rules
  rpc SetRouteRules     (SetRouteRulesRequest)  returns (SetRouteRulesResponse);
  rpc GetRouteRules     (GetRouteRulesRequest)  returns (GetRouteRulesResponse);

  // Config
  rpc GetConfig         (GetConfigRequest)   returns (GetConfigResponse);
  rpc UpdateConfig      (UpdateConfigRequest) returns (UpdateConfigResponse);

  // Telemetry (alternative to WebSocket for clients that prefer gRPC)
  rpc StreamTelemetry   (TelemetryRequest)   returns (stream TelemetryEvent);
}
```

### Message Reference

#### `StartProxyRequest` / `StartProxyResponse`

```protobuf
message StartProxyRequest {
  // Full Xray JSON config string. If empty, uses the last saved config.
  string config_json = 1;
}

message StartProxyResponse {
  bool   ok    = 1;
  string error = 2;  // non-empty on failure
}
```

#### `StatusResponse`

```protobuf
message StatusResponse {
  string runner_state          = 1;  // RunnerState string
  string xray_version          = 2;  // installed version or ""
  int64  uptime_seconds        = 3;
  string tun_device            = 4;
  bool   tun_active            = 5;
  int32  active_tgp_sessions   = 6;
}
```

#### `DownloadXrayProgress`

```protobuf
message DownloadXrayProgress {
  int64  bytes_received = 1;
  int64  total_bytes    = 2;
  bool   done           = 3;
  string error          = 4;
}
```

#### `RouteRule`

```protobuf
message RouteRule {
  // Exactly one of the following must be set:
  string process_name = 1;  // e.g. "cs2.exe"
  string geoip_code   = 2;  // e.g. "CN" → route CN traffic direct
  string domain_suffix = 3; // e.g. "steam.com"
  string cidr          = 4; // e.g. "10.0.0.0/8"

  enum Action {
    ACTION_UNSPECIFIED = 0;
    ACTION_TGP         = 1;
    ACTION_XRAY        = 2;
    ACTION_DIRECT      = 3;
    ACTION_DROP        = 4;
  }
  Action action   = 5;
  int32  priority = 6;  // higher = evaluated first
}
```

---

## 3. Error Codes

| Code | Meaning |
|---|---|
| `CORE_NOT_READY` | Core has not finished initialising |
| `XRAY_NOT_INSTALLED` | No xray binary found; call DownloadXray first |
| `XRAY_ALREADY_RUNNING` | StartProxy called while runner is in Running state |
| `INVALID_CONFIG` | JSON config failed validation |
| `TUN_PERMISSION_DENIED` | Insufficient OS privileges to create TUN device |
| `DOWNLOAD_CHECKSUM_MISMATCH` | Downloaded archive SHA-256 does not match |

---

## 4. Telemetry Interval Configuration

Prism can request a different telemetry interval via the `UpdateConfig` RPC:

```jsonc
// UpdateConfigRequest.patch
{
  "ipc": {
    "telemetry_interval_ms": 100  // minimum 100ms, maximum 5000ms
  }
}
```

---

## 5. Authentication (Future)

For security, a future version will require Prism to present a session token
issued by Core on startup. Core writes the token to a well-known file path
readable only by the current user:

```
Windows: %APPDATA%\Tachyon\core.token
macOS:   ~/Library/Application Support/Tachyon/core.token
Linux:   ~/.config/tachyon/core.token
```

Prism reads this file and sends it as the `Authorization: Bearer <token>`
HTTP header on WebSocket upgrade and as gRPC metadata on each call.
