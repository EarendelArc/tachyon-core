# Tachyon Core

[中文说明](README.zh-CN.md)

**Tachyon Core** is the unified network daemon for the Tachyon system.
A single binary operates in two modes — client or server — by changing a single
line in the config file. This mirrors the xray-core model: same binary, same
protocol, different config.

```
tachyon-core run --config client.yaml   # client: TUN + routing + Xray/TGP client
tachyon-core run --config server.yaml   # server: mux + TGP relay + Xray backend
```

---

## Architecture at a Glance

```
One Binary — Two Modes

CLIENT MODE                              SERVER MODE
──────────────────────────────────       ──────────────────────────────────
 OS traffic (TUN virtual NIC)             :443 TCP  → Xray backend (VLESS)
    │                                     :443 UDP  → TGP relay
    ▼
 PID Tracker (who sent this?)
    │
    ▼
 Routing Engine (rules-based)
    ├── TCP web  → Xray subprocess
    └── UDP game → TGP client session
```

---

## Architecture Rules

- Prism (UI) communicates with Core only via IPC (WebSocket + gRPC). Never directly.
- Xray-core is **never compiled in**. It runs as an external managed process.
- TCP proxy traffic and game UDP traffic use separate transport paths end-to-end.
- All platform-specific code is hidden behind narrow interfaces.
- `internal/mux` (server) and `internal/tun` (client) are mutually exclusive code paths.

---

## Implementation Status

| Module | Status | Description |
|---|---|---|
| `internal/config` | ✅ Done | Unified YAML config, client+server modes |
| `internal/routing` | ✅ Done | Priority rule engine, CIDR/process/domain/geoip |
| `internal/xray/runner.go` | ✅ Done | `ProxyRunner` interface + `SubProcessRunner` |
| `internal/xray/manager.go` | ✅ Done | `XrayManager` interface |
| `internal/xray/github.go` | ✅ Done | GitHub API release fetcher + resumable download |
| `internal/tgp/protocol.go` | ✅ Done | Wire structs + all interfaces |
| `internal/tgp/pacer.go` | ✅ Done | Token-Bucket pacer (anti-Bufferbloat) |
| `internal/tun/device.go` | ✅ Done | Cross-platform interface |
| `internal/tun/tun_linux.go` | ✅ Done | `/dev/net/tun` + netlink |
| `internal/tun/tun_darwin.go` | ✅ Done | `utun` socket |
| `internal/tun/tun_windows.go` | 🔲 Stub | Wintun (M5) |
| `internal/pidtrack/tracker.go` | ✅ Done | Cache + retry wrapper |
| `internal/pidtrack/linux.go` | ✅ Done | `/proc/net` inode join |
| `internal/pidtrack/windows.go` | ✅ Done | `GetExtendedTcpTable` + iphlpapi |
| `internal/pidtrack/darwin.go` | 🔲 Stub | libproc (M1) |
| `internal/mux/multiplexer.go` | ✅ Done | Port-443 TCP/UDP dispatcher |
| `internal/app/app.go` | ✅ Done | Wiring + startup/shutdown lifecycle |
| `cmd/tachyon-core/main.go` | ✅ Done | CLI with run/version/generate-config |
| `internal/tgp/session.go` | 🔲 M3 | TGP session state machine |
| `internal/tgp/fec.go` | 🔲 M3 | Reed-Solomon FEC encode/decode |
| `internal/tgp/crypto.go` | 🔲 M3 | ChaCha20-Poly1305 AEAD |
| `internal/ipc/` | 🔲 M4 | WebSocket + gRPC server for Prism |
| Full server mode wiring | 🔲 M3 | Connect mux → xray runner → TGP relay |
| Full client mode wiring | 🔲 M1 | Connect TUN → pidtrack → routing → xray/TGP |

---

## Milestone Plan

```
M1 — Pipeline Skeleton (current)
  ✅ Config, routing engine, TUN interfaces, PID tracking
  ✅ Mux, app wiring, CLI entry point
  🔲 Connect all client-mode pieces into a working (non-TGP) pipeline
  🔲 Linux integration test: route packets via Xray

M2 — Xray Integration
  🔲 Auto-download + verify xray binary at startup if missing
  🔲 Generate xray config from tachyon config
  🔲 Server mode: full xray subprocess management
  🔲 Client mode: Xray SOCKS5 inbound integration

M3 — TGP Core
  🔲 TGP session handshake (X25519 key exchange)
  🔲 ChaCha20-Poly1305 AEAD encrypt/decrypt
  🔲 Reed-Solomon FEC encode/decode
  🔲 Token-Bucket pacing (done) wired into session send path
  🔲 Connection migration on IP change
  🔲 Server-side TGP relay complete

M4 — IPC + Prism Integration
  🔲 WebSocket telemetry push (telemetry events every 500ms)
  🔲 gRPC control plane (StartProxy, StopProxy, DownloadXray, SetRouteRules)
  🔲 Prism ↔ Core integration test

M5 — Windows Production
  🔲 Wintun adapter (tun_windows.go full implementation)
  🔲 tachyon-helper.exe privilege separation service
  🔲 Windows installer (.msi or Inno Setup)
```

---

## Development Environment

```bash
# Install Go (required: 1.23+)
# https://go.dev/dl/

# Clone
git clone https://github.com/tachyon-space/tachyon-core
cd tachyon-core

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Build
go build -o bin/tachyon-core ./cmd/tachyon-core

# Generate a config template
./bin/tachyon-core generate-config --mode client > client.yaml
./bin/tachyon-core generate-config --mode server > server.yaml
```

## Server Deployment

```bash
# Bare metal (Debian/Ubuntu)
sudo bash scripts/install-server.sh \
  --domain vpn.example.com \
  --email  admin@example.com

# Docker Compose
sudo bash scripts/install-server-docker.sh \
  --domain vpn.example.com \
  --email  admin@example.com
```

See [docs/ipc-api.md](docs/ipc-api.md) for the Prism ↔ Core IPC API reference.
See [docs/tgp-spec.md](docs/tgp-spec.md) for the TGP wire format specification.
