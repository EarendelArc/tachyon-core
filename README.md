# Tachyon Core

[中文说明](README.zh-CN.md)

Tachyon Core is the headless network daemon for Tachyon. It follows the
xray-core operating model: one binary, two modes, explicit JSON configuration.

```bash
tachyon-core run --config client.json
tachyon-core run --config server.json
```

## Design Boundary

- Prism owns subscription retrieval, subscription parsing, node selection, and
  future Core/Xray config generation.
- Core owns packet capture, process-aware routing, Xray subprocess lifecycle,
  TGP transport, and server relay behavior.
- Xray-core is never compiled into Tachyon Core. It is downloaded, verified, and
  launched as an external subprocess.
- TCP proxy traffic and UDP game traffic use separate end-to-end paths.
- JSON is the canonical Core config format. Legacy YAML is accepted only for
  early developer compatibility.
- Relative file paths in Core JSON, including `xray.config_file`, are resolved
  from the directory that contains the loaded config file.

## Architecture

```text
Client mode
  TUN device -> PID tracker -> routing engine
    TCP web traffic  -> local Xray subprocess
    UDP game traffic -> TGP client session

Server mode
  :443 TCP/UDP listener
    TLS ClientHello -> local Xray backend
    TGP/DTLS packet -> TGP relay
```

## Implementation Status

| Area | Status |
| --- | --- |
| Unified client/server CLI | Done |
| JSON config loading and generation | Done |
| Process-aware routing profiles | Done |
| Manual game-mode profile API | Done |
| Steam library scan API | Done |
| Linux TUN and PID tracking | Done |
| Windows PID tracking | Done |
| macOS TUN | Done |
| Windows TUN | Stub |
| macOS PID tracking | Stub |
| Xray subprocess runner | Done |
| Xray client config generation | Done |
| TGP X25519 handshake and AEAD | Done |
| TGP UDP relay skeleton | Done |
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
sudo bash scripts/install-server.sh \
  --domain vpn.example.com \
  --email admin@example.com

sudo bash scripts/install-server-docker.sh \
  --domain vpn.example.com \
  --email admin@example.com
```

See [docs/ipc-api.md](docs/ipc-api.md) for Prism/Core IPC design notes and
[docs/tgp-spec.md](docs/tgp-spec.md) for the TGP wire format.
