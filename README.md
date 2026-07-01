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

Tachyon Core is not a production-complete release yet. The protocol and
pipeline are ready for alpha integration. Windows TUN now has an alpha dynamic
`wintun.dll` backend, but it still requires runtime validation with elevated
adapter creation on real Windows hosts.

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

## Server Deployment

```bash
sudo bash scripts/install-server.sh --port 443

sudo bash scripts/install-server-docker.sh --port 443
```

Both installers download the matching Linux ZIP asset from
`EarendelArc/tachyon-core` GitHub Releases. `--version latest` selects the
newest release entry, including alpha prereleases; pass an explicit tag such as
`--version v0.1.0-alpha.11` for reproducible deployment. The Docker path mounts
the downloaded static `tachyon-core` binary into a `debian:bookworm-slim`
container and does not depend on a GHCR image.

See [docs/ipc-api.md](docs/ipc-api.md) and
[docs/ipc-api.zh-CN.md](docs/ipc-api.zh-CN.md) for Prism/Core IPC design notes.
See [docs/tgp-spec.md](docs/tgp-spec.md) for the TGP wire format.
See [docs/release.md](docs/release.md) for GitHub release assets used by Prism.
