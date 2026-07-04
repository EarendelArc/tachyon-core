# Tachyon Core

[中文说明](README.zh-CN.md)

Tachyon Core is the headless transport core for the Tachyon game protocol. Its
role is similar to `xray-core`: it is a standalone network core with explicit
JSON configuration, but its protocol is designed for low-latency, low-loss game
traffic instead of general TCP proxying.

```bash
# Validate config without starting the daemon
tachyon-core validate --config client.json

# Start the core daemon
tachyon-core run --config client.json
tachyon-core run --config server.json

# Check if a running Core is healthy
tachyonctl health
tachyonctl health --addr 127.0.0.1:55123
```

## Design Boundary

- Prism owns subscription retrieval, subscription parsing, node selection,
  Xray lifecycle, Xray JSON generation, game profile management, launcher
  scanning, and desktop orchestration.
- Core owns Tachyon protocol transport: packet capture, process-aware game
  routing, TGP client transport, and TGP server relay behavior.
- Xray has no runtime or build-time dependency inside Tachyon Core.
- TCP proxy traffic belongs to Prism/Xray. UDP game traffic belongs to
  Tachyon Core/TGP.
- Client TUN defaults to TGP-only safe mode: `auto_route` and `dns_hijack` are
  off unless explicitly enabled by Prism or a hand-written config.
- JSON is the canonical Core config format. Legacy YAML is accepted only for
  early developer compatibility.
- Relative file paths in Core JSON are resolved from the directory that contains
  the loaded config file.

## Architecture

```text
Client mode
  TUN device -> PID tracker -> routing engine
    UDP game traffic -> TGP client session
    TCP/proxy traffic -> ignored by Core; Prism/Xray owns this path

Server mode
  UDP listener -> TGP relay -> real game server
```

## Implementation Status

Tachyon Core is not a stable or production-complete release yet. The protocol
and pipeline are ready for alpha integration. Client TUN auto-route and DNS
hijack stay disabled by default, and Windows TUN still requires runtime
validation with elevated adapter creation on real Windows hosts.

| Area | Status |
| --- | --- |
| Unified client/server CLI | Done |
| JSON config loading and generation | Done |
| Embedded Prism game profiles in Core JSON | Done |
| Process-aware routing profiles | Done |
| Local HTTP routing bridge compatibility | Done |
| tachyonctl health CLI | Done |
| tachyon-core validate (dry-run) | Done |
| Linux TUN and PID tracking | Done |
| Windows PID tracking | Done |
| macOS TUN | Done |
| Windows TUN | Alpha dynamic Wintun backend |
| macOS PID tracking | Alpha lsof/ps backend |
| TGP X25519 handshake and AEAD | Done |
| Multipath transport adapter | Done; interface discovery not wired |
| Persistent TGP UDP relay pool | Done |
| Client TUN -> routing -> TGP writeback test | Done |

## Development

This repository uses `mise` to manage Go.

```bash
mise install
mise exec -- go test ./...
mise exec -- go build ./...
mise exec -- go run ./cmd/tachyon-core generate-config --mode client > client.json
```

Before deploying a VPS, run the local TGP relay smoke test:

```bash
bash scripts/smoke-tgp-relay.sh
```

It uses only temporary `127.0.0.1` UDP ports and checks PSK handshake behavior,
missing/wrong PSK rejection, ACL allow/deny behavior, deny-all defaults,
wildcard target rejection, and an echo-like UDP relay round trip without
starting TUN or changing routes, firewall, systemd, Docker, or proxy state. This
local smoke test does not replace real VPS, real client, or real game UDP
validation.

## Server Deployment

```bash
sudo bash scripts/install-server.sh --port 443 \
  --allow-target 'cidr=198.51.100.0/24,ports=27015-27050'

sudo TACHYON_ALLOWED_TARGETS='domain=game.example.com,ports=27015' \
  bash scripts/install-server-docker.sh --port 443
```

Both installers download the matching Linux ZIP asset from
`EarendelArc/tachyon-core` GitHub Releases. `--version latest` selects the
newest release entry, including alpha prereleases; pass an explicit tag such as
`--version v0.1.0-alpha.14` for reproducible deployment. The Docker path mounts
the downloaded static `tachyon-core` binary into a `debian:bookworm-slim`
container and does not depend on a GHCR image.

Server relay security is fail-closed. The installer generates a fresh
`tgp.auth.psk` and writes it to `server.json`; copy that PSK into the Prism
Tachyon server profile. `server.relay.allowed_targets` is an explicit UDP
allow-list. If no targets are supplied, the server starts in safe deny-all mode
and will not forward game UDP until you edit the config. Wildcard targets such
as `0.0.0.0/0` and `::/0` are rejected, and each allow rule must include an
explicit `ports` list or range. Relay path migration/rebind is currently
fail-closed; future protocol work will add an authenticated rebind control path.

After deployment, collect read-only diagnostics with:

```bash
sudo bash scripts/verify-server.sh
sudo bash scripts/verify-server.sh --mode docker
bash scripts/verify-server.sh --mode config --binary ./tachyon-core --config ./server.json
```

Send us the full output when asking for help with VPS relay validation. The
verify script redacts PSK values and does not change firewall rules, but still
review the output before posting it publicly. Never paste or publish
`tgp.auth.psk`; share only whether it is present/non-placeholder and the
`allowed_targets` summary.

See [docs/tgp-server-verification.md](docs/tgp-server-verification.md) for the
full local smoke and VPS verification checklist.

See [docs/ipc-api.md](docs/ipc-api.md) and
[docs/ipc-api.zh-CN.md](docs/ipc-api.zh-CN.md) for Prism/Core IPC design notes.
See [docs/tgp-spec.md](docs/tgp-spec.md) for the TGP wire format.
See [docs/release.md](docs/release.md) for GitHub release assets used by Prism.
