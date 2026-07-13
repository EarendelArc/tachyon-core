# Changelog

All notable changes to Tachyon Core will be documented in this file.

## [Unreleased]

### Changed
- TGP v3 authenticates and negotiates the 1232-1452 byte encrypted datagram
  budget, carries relay time for path-request clock alignment, rejects v1/v2
  peers, and records oversized receive drops.
- Relay return-path selection is now controlled only by fresh path challenge
  completion; authorized business data from old paths cannot switch it.
- Relay paths now expire and safely replace the least-recently-used inactive
  entry instead of permanently exhausting the eight-path session bound.
- Path requests now carry an authenticated 10-second timestamp. A fixed-state
  global bucket bounds unauthenticated HMAC work, while only valid HMACs consume
  the strict per-CID response quota.
- Codec and FEC processing now enforce protocol limits for datagram size,
  shard counts and size, active/completed groups, and total buffered bytes.
- The default client TUN MTU is now 1280 with a 1352-byte TGP budget. The
  audited worst-case packet with FEC and outer IPv6/UDP headers is 1396 bytes,
  while explicit protocol limits and the 1232-byte low-PMTU preset remain.
- TGP packet-number deduplication is now a sliding anti-replay window: packets
  older than the retained window remain rejected instead of becoming eligible
  again after insertion-order eviction.

### Added
- Added stateless source-bound path cookies with a bounded per-session response
  replay set, eliminating PathRequest-controlled global pending state.
- Added client multipath source authorization for configured relay endpoints.
  A forwarded valid challenge cannot bootstrap an unknown server address;
  server endpoint migration requires a new handshake.
- Added per-session path request/challenge/response authentication for relay
  migration and multipath sources. Additional UDP sources are registered only
  after proving possession of an ECDH-derived path key from the requesting
  source with a short-lived, one-time server challenge.

### Fixed
- Valid ciphertext from an unknown client-side multipath source is rejected
  before it can consume anti-replay state or update the session remote.
- Replayed authenticated packets can no longer update a session's return path;
  source authorization and anti-replay checks complete before migration state
  changes.
- Linux IPv4/IPv6 and Windows IPv4 UDP process tracking now falls back to
  wildcard socket bindings after checking exact local-address matches, so
  process-based game profiles can identify games that bind `0.0.0.0` or `::`
  before sending.

## [v0.1.0-alpha.14] - 2026-07-04

### Added
- Added `scripts/smoke-tgp-relay.sh` as a local TGP relay smoke verification
  entry point. It runs the focused relay smoke test without touching TUN,
  system proxy, routes, firewall, systemd, Docker, or a real VPS.
- The smoke coverage exercises PSK-authenticated handshakes, missing/wrong PSK
  rejection, ACL allow/deny behavior, deny-all defaults, wildcard target
  rejection, and an echo-like UDP relay round trip on temporary `127.0.0.1`
  ports.
- Added TGP server verification documentation that separates local smoke checks
  from post-deployment VPS acceptance checks.

### Changed
- Release and README guidance now makes the alpha boundary explicit: Core is
  not stable or complete, client TUN routing remains disabled by default, local
  smoke does not replace real VPS/client/game UDP validation, and deployed
  servers should still be checked with `scripts/verify-server.sh`.
- Server deployment notes continue to require a private `tgp.auth.psk`, explicit
  `server.relay.allowed_targets`, and no public sharing of PSK values.

### Known Limitations
- Client TUN auto-route and DNS hijack remain disabled by default for alpha.
- Local relay smoke verification is not a real network test; real VPS security
  groups, client paths, carrier UDP reachability, and target game UDP behavior
  still need field validation.
- Relay path rebind/migration remains fail-closed until an authenticated rebind
  control path exists.
- Windows TUN still needs elevated validation on real Windows hosts.

### 中文说明
- 新增 `scripts/smoke-tgp-relay.sh`，作为本地 TGP relay smoke 验证入口。
  该脚本只运行聚焦的 relay smoke，不会启用 TUN、系统代理，也不会修改路由、
  防火墙、systemd、Docker 或真实 VPS。
- smoke 覆盖带 PSK 的握手、缺失/错误 PSK 拒绝、ACL allow/deny、默认
  deny-all、通配全网目标拒绝，以及临时 `127.0.0.1` UDP 端口上的 echo-like
  relay 往返。
- README 和 release 说明明确 alpha 边界：Core 还不是 stable/完整版本，客户端
  TUN 路由默认关闭，本地 smoke 不能替代真实 VPS、客户端和游戏 UDP 验证；
  部署后仍应运行 `scripts/verify-server.sh`。
- 服务端部署仍要求使用私有 `tgp.auth.psk` 和显式 `server.relay.allowed_targets`；
  不要公开或粘贴 PSK 原文。

## [v0.1.0-alpha.13] - 2026-07-04

### Added
- Added and documented `scripts/verify-server.sh` as a non-destructive server
  acceptance helper for alpha deployments. It can inspect bare-metal systemd
  installs, Docker Compose installs, and local config/binary pairs without
  starting new relay traffic.
- The verification helper reports systemd unit/service state, Docker Compose
  service state, config validation results, relay listen settings, and a
  redacted `allowed_targets` summary so operators can confirm whether the
  server is still in deny-all mode.
- Added CI bash self-check coverage for the server verification script so
  syntax and fixture-based diagnostics stay exercised before release.

### Changed
- Server diagnostics now keep `tgp.auth.psk` redacted and do not print raw PSK
  values in config summaries or command output.
- The release notes call out that the script is an alpha acceptance aid, not a
  substitute for real VPS, Docker, or target-game UDP validation.

### Known Limitations
- Real VPS and Docker host validation is still required for this preview.
- The verification helper only summarizes configured `allowed_targets`; it does
  not prove remote game reachability or relay policy correctness in the target
  network.

### 中文说明
- 新增并强化 `scripts/verify-server.sh`，用于 alpha 服务端部署后的非破坏性验收。
  脚本可检查裸机 systemd、Docker Compose 以及本地 config/binary 组合，不会主动
  发起新的 relay 流量。
- 诊断输出包含 systemd/docker 状态、配置校验结果、监听配置和脱敏后的
  `allowed_targets` 摘要，便于确认服务端是否仍处于安全 deny-all 模式。
- 诊断不会输出 `tgp.auth.psk` 原文，避免在日志或终端记录中泄露 PSK。
- CI 增加 bash 自检，覆盖验收脚本的语法和基于 fixture 的诊断路径。
- 仍需在真实 VPS 和 Docker 主机上做 alpha 验证；脚本摘要不能替代真实游戏 UDP
  可达性和目标网络中的 relay 策略验证。

## [v0.1.0-alpha.12] - 2026-07-03

### Changed
- Replaced the server's one-shot UDP forwarder with a persistent per-session,
  per-flow UDP relay pool. Upstream game sockets are now reused and background
  read loops can forward asynchronous game responses back over the TGP session.
- Changed client TUN defaults to TGP-only safe mode: `auto_route` and
  `dns_hijack` now default to `false` so Core does not capture unrelated
  Prism/Xray traffic unless explicitly configured.
- Server mode now requires `tgp.auth.psk` by default; unauthenticated relay mode
  must be enabled explicitly with `tgp.auth.allow_unauthenticated` for local
  development.
- Server installers now keep relay forwarding in safe deny-all mode unless
  explicit `server.relay.allowed_targets` are supplied, and reject wildcard
  targets or entries without explicit ports.
- Relay path migration/rebind is documented as fail-closed until a future
  authenticated rebind control path is added.
- Client TUN direct decisions now fail explicitly in TGP-only mode instead of
  being silently consumed by Core.

### Added
- Optional TGP PSK authentication. When configured, PSK-backed HMAC tags are
  required during handshake and the PSK is mixed into traffic-key derivation.
- Client-side TGP multipath configuration wiring: `client.proxy.local_addrs`
  now feeds the TGP client manager, single-address binding is honored, and
  multi-address configs use the multipath transport adapter.
- `tgp.connection_migration` now gates authenticated source-address migration
  in client and server TGP sessions; disabling it drops packets from unexpected
  paths instead of silently rebinding the session.
- Server config templates and install scripts now generate TGP relay configs
  with `tgp.multipath` disabled because multipath is a client-side local-bind
  feature.
- Server config templates and installers now include relay ACL examples and
  resource-limit defaults for sessions, queues, handler concurrency, and UDP
  flows.
- Server relay ACL validation defaults to deny-all and requires explicit
  `server.relay.allowed_targets` entries with `ports`; wildcard CIDRs such as
  `0.0.0.0/0` and `::/0` are rejected.
- TGP relay now accepts multiple concurrent client sessions and demuxes data
  packets by authenticated UDP source address. Unknown non-handshake UDP
  packets fail closed instead of being broadcast to all sessions.
- Relay resource limits for max sessions, per-session packet queues, handler
  concurrency, total UDP flows, and per-session UDP flows.
- Bare-metal and Docker server installers now accept safe relay target inputs
  via `--allow-target` or `TACHYON_ALLOWED_TARGETS`, keep deny-all when omitted,
  and validate listener ports as numeric `1..65535`.
- `tgp.pacing.max_rate_pps` now acts as a hard ceiling for the initial TGP
  pacer rate used by both client and server modes.
- Config validation for malformed `client.proxy.local_addrs` entries and
  multipath configs with fewer than two local bind addresses or disabled
  connection migration.
- Tests covering asynchronous server UDP relay responses, TGP relay echo, and
  TUN writeback through the persistent relay path.
- Tests covering multipath handshakes, manager dial selection, and
  `local_addrs` config loading.

### Fixed
- Server bare-metal and Docker installers now download `SHA256SUMS.txt` and
  verify the selected release archive before extracting `tachyon-core`.
- Server installers now generate a random TGP PSK, write it into `server.json`,
  and create the config file with restrictive permissions before writing so
  local users cannot casually read the shared secret.
- Handshake failures now surface a dedicated `ErrHandshakeTimeout` wrapper
  while preserving the underlying context deadline/cancellation cause.

### Known Limitations
- Relay path rebind/migration is fail-closed until a future authenticated
  rebind control path is implemented.
- Windows TUN still needs elevated validation on real Windows hosts.
- Real VPS and real game-server relay paths still need alpha field validation.
- Domain-based relay ACL entries are resolved at Core startup and do not track
  DNS changes dynamically.

## [v0.1.0-alpha.6] - 2026-06-28

### Fixed
- Made executable path matching independent of the CI runner OS by normalizing Windows and POSIX separators with portable path semantics.
- Prevented path-prefix game rules from matching adjacent sibling directories such as `C:\Games2`.

## [v0.1.0-alpha.5] - 2026-06-28

### Added
- Byte-level telemetry counters for pipeline read bytes, TGP-routed bytes, direct bytes, and dropped bytes.
- TGP session byte counters exposed through the observability collector for Prism dual-core traffic charts.
- Tests covering pipeline byte accounting, observability snapshots, and telemetry event serialization.

### Changed
- Telemetry SSE payloads now include byte fields while preserving existing packet and decision counters.

## [v0.1.0-alpha.4] - 2026-06-28

### Changed
- Hardened the local release script's Go tool discovery for mise-managed environments.

### Added
- Real-time SSE telemetry stream at `/v1/telemetry/sse` with hello, telemetry, route_event, tgp_session, and error events.
- `internal/observability` package: event types, stats collector, SSE broadcaster (16 tests).
- `Pipeline` stats accessor methods satisfying `observability.PipelineStats` interface.
- `ClientManager.ActiveSessions()` for telemetry session counting.
- Config validation: `server.listen` required in server mode, negative `max_rate_pps` rejected.
- Routing store validation and config tests (13 tests).
- Routing engine profile matching coverage (8 new edge-case tests).
- HTTP bridge test expansion: health endpoint, PUT update, 404/409/400 error paths (9 new tests).

## [v0.1.0-alpha.2]

### Added
- `tachyonctl health` CLI command with `--addr/-a` flag to query Core health endpoint.
- `tachyon-core validate --config` dry-run mode that loads config without starting the daemon.
- `internal/cli` package extracting CLI logic into testable functions (26 tests).
- `--help/-h` flags on both `tachyon-core` and `tachyonctl` top-level and subcommands.
- `FlagValue` helper for reusable argument parsing.
- Implementation status table entries for new commands.

### Changed
- `cmd/tachyon-core/main.go` reduced from ~270 to ~133 lines via `internal/cli` extraction.
- `cmd/tachyonctl/main.go` reduced from ~67 to ~52 lines.

## [v0.1.0-alpha.1]

### Added
- Client/server mode unified CLI with JSON config.
- Process-aware game routing engine with manual profiles, launcher child-process tracking, and Steam app detection.
- TGP (Tachyon Game Protocol) with X25519 handshake, AEAD, FEC, pacing, and UDP relay.
- Cross-platform TUN: Linux (done), macOS (done), Windows (alpha Wintun dynamic backend).
- Cross-platform PID tracking: Linux procnet, Windows, macOS lsof/ps.
- Local HTTP bridge (`127.0.0.1:55123`) with game profile CRUD and Steam scan endpoints.
- Config generation templates (`generate-config --mode client/server`).
- Server deployment scripts (`install-server.sh`, `install-server-docker.sh`).
- GitHub Actions CI (test + cross-compile) and release workflow (7 platform binaries + SHA256SUMS).
- Comprehensive documentation: IPC API, TGP spec, game-mode routing, architecture, development.
- 136 tests across 29 test files.

