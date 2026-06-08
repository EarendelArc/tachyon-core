# Changelog

All notable changes to Tachyon Core will be documented in this file.

## [Unreleased]

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

