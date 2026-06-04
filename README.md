# Tachyon Core

[中文说明](README.zh-CN.md)

Tachyon Core is the headless daemon for Tachyon.

It owns packet capture, process-aware routing, Xray lifecycle management, and
the Tachyon Game Protocol client path for latency-sensitive UDP traffic.

## Architecture Rules

- Prism talks to Core through IPC only.
- Xray runs as an external managed binary and is never compiled into Core.
- TCP proxy traffic and game UDP traffic use separate transport paths.
- Manual game profiles have higher priority than automatic detection.
- Platform-specific code lives behind narrow interfaces.

## First Milestones

1. Run a mock TUN pipeline and route decisions from process metadata.
2. Manage Xray as a subprocess through `ProxyRunner`.
3. Add TGP loopback UDP sessions with pacing metrics.
4. Add platform PID tracking providers for Windows, macOS, and Linux.

## Development Environment

This repository uses `mise` for tool version management.

```bash
mise install
go test ./...
```

The pinned Go version is declared in `.tool-versions`.
