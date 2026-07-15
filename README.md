# Tachyon Core

[中文说明](README.zh-CN.md)

Tachyon Core is the headless transport core for the Tachyon game protocol. Its
role is similar to `xray-core`: it is a standalone network core with explicit
JSON configuration, but its protocol is designed for low-latency, low-loss game
traffic instead of general TCP proxying.

```bash
# Validate config without starting the daemon
tachyon-core validate --config client.json

# Explain client TUN/Wintun/permission readiness without starting the daemon
tachyon-core doctor --config client.json --json
tachyon-core preflight --config client.json --json

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
- Client TUN is TGP-only: `auto_route=true`, `dns_hijack=true`, and
  `tgp_only=false` fail config validation because Core has no native direct or
  DNS forwarding path. On Windows, Core transactionally installs only the
  explicit CIDRs in `client.tun.game_routes`; Linux and macOS currently reject
  non-empty `game_routes` before creating a TUN. Core never falls back to a
  default route.
- `game_routes` are destination routes, not process routes. Every process that
  contacts one of those CIDRs enters the TUN. PID/game-profile decisions still
  decide whether a captured UDP packet may use TGP, but they cannot make the OS
  route distinguish two processes contacting the same destination CIDR.
- With non-empty `game_routes`, every currently resolved TGP Relay A/AAAA
  address is excluded by validation. If a Relay address overlaps a game route,
  startup fails before TUN creation; a later DNS change into a game route is
  rejected before a TGP reconnect. Empty `game_routes` performs no Relay DNS
  pre-resolution and no OS route mutation.
- Client route rules support process name, CIDR, and protocol matching.
  `domain` and `geoip` rules fail validation until Core has implementations
  that can make deterministic packet-path decisions.
- JSON is the canonical Core config format. Legacy YAML is accepted only for
  early developer compatibility.
- Relative file paths in Core JSON are resolved from the directory that contains
  the loaded config file.

## Architecture

```text
Client mode
  OS selective game routes -> TUN device -> PID tracker -> routing engine
    UDP game traffic -> TGP client session
    direct decision -> fail closed (must not have been captured)

Server mode
  UDP listener -> TGP relay -> real game server
```

## Implementation Status

Tachyon Core is not a stable or production-complete release yet. The protocol
and pipeline are ready for alpha integration. Client TUN auto-route and DNS
hijack are currently unsupported and rejected by config validation, and Windows
TUN still requires runtime validation with elevated adapter creation on real
Windows hosts.

| Area | Status |
| --- | --- |
| Unified client/server CLI | Done |
| JSON config loading and generation | Done |
| Embedded Prism game profiles in Core JSON | Done |
| Process-aware routing profiles | Done |
| Local HTTP routing bridge compatibility | Done |
| tachyonctl health CLI | Done |
| tachyon-core validate (dry-run) | Done |
| tachyon-core doctor/preflight (read-only) | Done |
| Linux TUN and PID tracking | Done |
| Windows PID tracking | Done |
| macOS TUN | Done |
| Windows TUN | Alpha dynamic Wintun backend with transactional destination routes |
| Linux/macOS selective destination routes | Fail-closed; not enabled yet |
| macOS PID tracking | Alpha lsof/ps backend |
| TGP X25519 handshake and AEAD | Done |
| Multipath transport adapter | Done; interface discovery not wired |
| Authenticated relay path migration | Done; ECDH-derived challenge-response |
| Persistent TGP UDP relay pool | Done |
| Client TUN -> routing -> TGP writeback test | Done |

## Development

This repository uses `mise` to manage Go.

```bash
mise install
mise exec -- go test ./...
mise exec -- go build ./...
mise exec -- go run ./cmd/tachyon-core generate-config --mode client > client.json
mise exec -- go run ./cmd/tachyon-core doctor --config client.json --json
mise exec -- go run ./cmd/tachyon-core preflight --config client.json --json
```

`tachyon-core doctor` is a read-only preflight command intended for Prism
startup orchestration. `tachyon-core preflight` is an equivalent alias; use
whichever command name is clearer for the caller. Both commands load and
validate the config, report `game_routes` and the current TUN safety flags,
explain whether client mode requires TUN, and emit stable JSON checks such as
`CONFIG_VALID`,
`CLIENT_REQUIRES_TUN`, `WINTUN_DLL_PRESENT`, `TUN_DEVICE_PRESENT`,
`TUN_PRIVILEGE`, and `SELECTIVE_ROUTES_SUPPORTED`. Linux and macOS report a
non-empty `game_routes` list as a fail-closed startup error. The checks do not
create a persistent TUN adapter, change routes, start services, launch the
daemon, or alter firewall, system proxy, Docker, systemd, or packet filter state.

Before deploying a VPS, run the local TGP relay smoke test:

```bash
bash scripts/smoke-tgp-relay.sh
```

It uses only temporary `127.0.0.1` UDP ports and checks PSK handshake behavior,
missing/wrong PSK rejection, config-driven client/server relay wiring, ACL
allow/deny behavior, deny-all defaults, wildcard target rejection, and an
echo-like UDP relay round trip without starting TUN, invoking Prism/Xray, or
changing routes, firewall, systemd, Docker, or proxy state. This
local smoke test does not replace real VPS, real client, or real game UDP
validation.

## Server Deployment

```bash
sudo bash scripts/install-server.sh --port 443 \
  --ssh-port 22 \
  --allow-target 'cidr=198.51.100.0/24,ports=27015-27050'

sudo TACHYON_ALLOWED_TARGETS='domain=game.example.com,ports=27015' \
  bash scripts/install-server-docker.sh --port 443
```

Both installers download the matching Linux ZIP asset from
`EarendelArc/tachyon-core` GitHub Releases. `--version latest` selects the
newest release entry, including alpha prereleases; pass an explicit tag such as
`--version v0.1.0-alpha.15` for reproducible deployment. The Docker path mounts
the downloaded static `tachyon-core` binary into a `debian:bookworm-slim`
container and does not depend on a GHCR image.

The bare-metal installer can manage ufw for you. It opens the configured
Tachyon UDP port and keeps the SSH TCP port open before enabling ufw; pass
`--ssh-port PORT` on non-standard SSH hosts, or pass `--no-firewall` when a
cloud firewall, nftables, firewalld, or custom host policy is managed
separately. The generated systemd unit runs as the `tachyon` user, keeps only
`CAP_NET_BIND_SERVICE`, makes system paths read-only, and leaves only the log
directory writable.

The Docker installer intentionally uses `network_mode: host` to avoid Docker
NAT/userland proxy jitter for latency-sensitive UDP. The compose file is still
hardened with a read-only root filesystem, no-new-privileges, dropped default
capabilities, only `NET_BIND_SERVICE` restored, tmpfs scratch space, a health
check, and `restart: unless-stopped`. It does not modify host firewall rules.

Server relay security is fail-closed. The installer generates a fresh
`tgp.auth.psk` and writes it to `server.json`; copy that PSK into the Prism
Tachyon server profile. `server.relay.allowed_targets` is an explicit UDP
allow-list. If no targets are supplied, the server starts in safe deny-all mode
and will not forward game UDP until you edit the config. Wildcard targets such
as `0.0.0.0/0` and `::/0` are rejected, and each allow rule must include an
explicit `ports` list or range. Additional migration and multipath source
addresses are fail-closed until they complete a per-session, ECDH-derived
request/challenge/response exchange; replayed responses and data packets cannot
register a path. Challenges use stateless source-bound cookies, and only a
fresh completed challenge changes the active relay return path; business data
from an older authorized path cannot switch it.
Path requests have strict wire sizes and carry an authenticated 10-second
timestamp. Unknown session IDs are dropped before HMAC verification. A fresh
request for a known session is verified without allocating state or consuming
tokens; an invalid HMAC costs only stateless CPU work and receives no response.
Only valid HMACs reach the per-session burst-8, 2-per-second migration quota.

The generated client uses `client.tun.mtu=1280` and
`tgp.max_datagram_size=1352`, bounding its worst-case outer IPv6/UDP packet to
1396 bytes. The authenticated TGP v3 handshake negotiates the lower client and
relay budget, carries relay time for path-request clock alignment, and rejects
version 1/2 peers instead of guessing missing fields.
Known lower-PMTU paths can reduce the datagram limit to 1232 with a matching
TUN MTU. Core rejects inconsistent budgets, reports oversized receive drops,
and returns explicit errors for oversized sends. TGP does not yet provide
fragmentation or automatic PMTU discovery.

After deployment, collect read-only diagnostics with:

```bash
sudo bash scripts/verify-server.sh
sudo bash scripts/verify-server.sh --mode docker
bash scripts/verify-server.sh --mode config --binary ./tachyon-core --config ./server.json
```

For an explicit public TGP E2E check, use a controlled UDP echo target already
listed in `server.relay.allowed_targets`:

```bash
bash scripts/verify-tgp-e2e.sh --mode public \
  --server vps.example.com:443 \
  --target echo.example.com:27015 \
  --psk-file ./tgp.psk
```

The E2E verifier defaults to local loopback smoke and never contacts a public
UDP target unless `--server`, `--target`, and a PSK are provided. It does not
create TUN devices, change routes, alter firewall rules, manage services, or
invoke Prism. It proves only the Core/TGP client-to-relay-to-controlled-UDP-target
loop; it does not prove Prism integration, TUN capture, or real game traffic.

When asking for help with VPS relay validation, generate a timestamped support
bundle:

```bash
sudo bash scripts/collect-server-diagnostics.sh
sudo bash scripts/collect-server-diagnostics.sh --mode docker
sudo bash scripts/collect-server-diagnostics.sh --format txt
```

The collector includes OS/kernel details, Core version, config validation,
`allowed_targets`, service/container status, UDP listener state, redacted log
tails, and redacted `verify-server.sh` output. It is read-only and does not
change firewall, Docker, systemd, packet filter, route, or proxy state. Review
the generated `tachyon-server-diagnostics-*.tar.gz` or `.txt` before sending it
back. Never paste or publish `tgp.auth.psk`, full private subscription/proxy
URLs, tokens, UUIDs, private keys, API keys, or passwords; share only whether
PSK is present/non-placeholder and the `allowed_targets` summary.

See [docs/tgp-server-verification.md](docs/tgp-server-verification.md) for the
full local smoke and VPS verification checklist.

See [docs/alpha-test-plan.md](docs/alpha-test-plan.md) and
[docs/alpha-test-plan.zh-CN.md](docs/alpha-test-plan.zh-CN.md) for the
bilingual real VPS alpha relay test plan and redacted result checklist.

See [docs/ipc-api.md](docs/ipc-api.md) and
[docs/ipc-api.zh-CN.md](docs/ipc-api.zh-CN.md) for Prism/Core IPC design notes.
See [docs/tgp-spec.md](docs/tgp-spec.md) for the TGP wire format.
See [docs/release.md](docs/release.md) for GitHub release assets used by Prism.
