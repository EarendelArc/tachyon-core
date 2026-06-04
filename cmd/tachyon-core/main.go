// tachyon-core: cross-platform network daemon for the Tachyon system.
//
// Usage:
//
//	tachyon-core run --config /etc/tachyon/config.yaml
//	tachyon-core version
//	tachyon-core generate-config --mode client > config.yaml
//	tachyon-core generate-config --mode server > config.yaml
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tachyon-space/tachyon-core/internal/app"
	"github.com/tachyon-space/tachyon-core/internal/config"
)

// Version is injected at build time via -ldflags.
var (
	Version   = "dev"
	GoVersion = "unknown"
	BuildTime = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "version", "-v", "--version":
		fmt.Printf("tachyon-core %s (built %s with %s)\n", Version, BuildTime, GoVersion)
		return nil

	case "generate-config":
		return cmdGenerateConfig(args[1:])

	case "run":
		return cmdRun(args[1:])

	default:
		printUsage()
		return fmt.Errorf("unknown command: %q", args[0])
	}
}

// cmdRun is the primary subcommand that starts the daemon.
func cmdRun(args []string) error {
	configPath := "config.yaml"
	for i, a := range args {
		if (a == "--config" || a == "-c") && i+1 < len(args) {
			configPath = args[i+1]
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Setup structured logger before everything else.
	logger := buildLogger(cfg.Observability.LogLevel, cfg.Observability.LogFile)
	slog.SetDefault(logger)

	slog.Info("tachyon-core starting",
		"version", Version,
		"mode", cfg.Mode,
		"config", configPath,
	)

	// Build the application (dependency injection).
	application, err := app.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("initialise application: %w", err)
	}

	// Root context cancelled on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run blocks until the context is cancelled or a fatal error occurs.
	if err := application.Run(ctx); err != nil {
		return fmt.Errorf("application error: %w", err)
	}

	slog.Info("tachyon-core stopped cleanly")
	return nil
}

// cmdGenerateConfig prints a template config to stdout.
func cmdGenerateConfig(args []string) error {
	mode := config.ModeClient
	for i, a := range args {
		if (a == "--mode" || a == "-m") && i+1 < len(args) {
			mode = config.Mode(args[i+1])
		}
	}

	var tmpl string
	switch mode {
	case config.ModeClient:
		tmpl = clientConfigTemplate
	case config.ModeServer:
		tmpl = serverConfigTemplate
	default:
		return fmt.Errorf("unknown mode %q; use 'client' or 'server'", mode)
	}
	fmt.Print(tmpl)
	return nil
}

func buildLogger(level, logFile string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			return slog.New(slog.NewJSONHandler(f, opts))
		}
		// Fall through to stderr on error.
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func printUsage() {
	fmt.Fprint(os.Stderr, `tachyon-core — Tachyon network daemon

USAGE:
  tachyon-core <command> [options]

COMMANDS:
  run               Start the daemon (client or server mode)
    --config/-c     Path to config file (default: config.yaml)

  generate-config   Print a template config to stdout
    --mode/-m       "client" or "server" (default: client)

  version           Print version information

EXAMPLES:
  # Start as a client daemon
  tachyon-core run --config /etc/tachyon/client.yaml

  # Start as a server
  tachyon-core run --config /etc/tachyon/server.yaml

  # Generate a client config template
  tachyon-core generate-config --mode client > client.yaml
`)
}

// ---------------------------------------------------------------------------
// Embedded config templates
// ---------------------------------------------------------------------------

const clientConfigTemplate = `# Tachyon Core — Client Mode Configuration
mode: client

client:
  tun:
    name: ""            # auto-selected per platform
    address: "198.18.0.1/16"
    mtu: 9000
    auto_route: true
    dns_hijack: true

  routing:
    default_action: xray   # xray | tgp | direct | drop
    rules:
      # Example: route CS2 game traffic via TGP (low-latency UDP path)
      - process_name: cs2.exe
        action: tgp
        priority: 100

      # Example: bypass LAN traffic
      - cidr: "192.168.0.0/16"
        action: direct
        priority: 50

      # Example: bypass mainland China IPs
      - geoip: CN
        action: direct
        priority: 10

  proxy:
    server_addr: "your-server.example.com:443"
    vless_uuid: "00000000-0000-0000-0000-000000000000"
    sni: "your-server.example.com"

tgp:
  fec:
    data_shards: 4
    parity_shards: 2
    group_timeout: 20ms
  pacing:
    initial_rate_pps: 128
    max_rate_pps: 1000
  connection_migration: true
  multipath: false
  handshake_timeout: 5s
  session_idle_timeout: 60s

xray:
  install_dir: ""   # defaults to <data_dir>/xray/

ipc:
  websocket_addr: "127.0.0.1:9999"
  grpc_addr: "127.0.0.1:50051"
  telemetry_interval_ms: 500

observability:
  log_level: info
  log_file: ""        # empty = stderr only
  metrics_addr: ""    # empty = disabled
`

const serverConfigTemplate = `# Tachyon Core — Server Mode Configuration
mode: server

server:
  listen: ":443"

  tls:
    cert: "/etc/tachyon/certs/fullchain.pem"
    key:  "/etc/tachyon/certs/key.pem"

  xray_backend:
    addr: "127.0.0.1:18443"

  relay:
    dial_timeout: 5s
    idle_timeout: 60s

tgp:
  fec:
    data_shards: 4
    parity_shards: 2
    group_timeout: 20ms
  pacing:
    initial_rate_pps: 128
    max_rate_pps: 1000
  connection_migration: true
  multipath: true
  handshake_timeout: 5s
  session_idle_timeout: 300s

xray:
  install_dir: "/opt/tachyon/xray/"
  config_file: "/etc/tachyon/xray-server.json"

observability:
  log_level: info
  log_file: "/var/log/tachyon/tachyon-core.log"
  metrics_addr: "127.0.0.1:19090"
`
