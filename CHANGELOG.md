# Changelog

All notable changes to Tachyon Core will be documented in this file.

## [Unreleased]

### Changed
- Replaced the server's one-shot UDP forwarder with a persistent per-session,
  per-flow UDP relay pool. Upstream game sockets are now reused and background
  read loops can forward asynchronous game responses back over the TGP session.
- Changed client TUN defaults to TGP-only safe mode: `auto_route` and
  `dns_hijack` now default to `false` so Core does not capture unrelated
  Prism/Xray traffic unless explicitly configured.

### Added
- Client-side TGP multipath configuration wiring: `client.proxy.local_addrs`
  now feeds the TGP client manager, single-address binding is honored, and
  multi-address configs use the multipath transport adapter.
- `tgp.connection_migration` now gates authenticated source-address migration
  in client and server TGP sessions; disabling it drops packets from unexpected
  paths instead of silently rebinding the session.
- Server config templates and install scripts now generate TGP relay configs
  with `tgp.multipath` disabled because multipath is a client-side local-bind
  feature.
- `tgp.pacing.max_rate_pps` now acts as a hard ceiling for the initial TGP
  pacer rate used by both client and server modes.
- Config validation for malformed `client.proxy.local_addrs` entries and
  multipath configs with fewer than two local bind addresses or disabled
  connection migration.
- Tests covering asynchronous server UDP relay responses, TGP relay echo, and
  TUN writeback through the persistent relay path.
- Tests covering multipath handshakes, manager dial selection, and
  `local_addrs` config loading.

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

