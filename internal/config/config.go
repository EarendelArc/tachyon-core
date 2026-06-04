// Package config defines the unified configuration schema for tachyon-core.
//
// A single tachyon-core binary can operate in two modes:
//   - "client"  TUN stack + PID routing + Xray/TGP client session
//   - "server"  Port multiplexer + Xray backend + TGP relay
//
// The mode is selected by the top-level Mode field. Shared subsystems
// (TGP protocol parameters, observability) live at the top level.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode determines whether this instance behaves as a client or server.
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

// ---------------------------------------------------------------------------
// Root config
// ---------------------------------------------------------------------------

// Config is the top-level configuration object. It is loaded from a YAML file
// and optionally overridden by environment variables.
type Config struct {
	// Mode selects client or server operation. Required.
	Mode Mode `yaml:"mode"`

	// Client contains settings only relevant when Mode == "client".
	Client ClientConfig `yaml:"client,omitempty"`

	// Server contains settings only relevant when Mode == "server".
	Server ServerConfig `yaml:"server,omitempty"`

	// TGP contains settings shared between client and server TGP paths.
	TGP TGPConfig `yaml:"tgp"`

	// Xray contains settings for managing the xray-core binary.
	Xray XrayConfig `yaml:"xray"`

	// IPC controls the Prism ↔ Core communication endpoints.
	// Only meaningful in client mode.
	IPC IPCConfig `yaml:"ipc"`

	// Observability controls logging, metrics and tracing.
	Observability ObservabilityConfig `yaml:"observability"`
}

// ---------------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------------

// ClientConfig holds all client-side settings.
type ClientConfig struct {
	// TUN configures the virtual network interface.
	TUN TUNConfig `yaml:"tun"`

	// Routing defines the rule-based traffic classification engine.
	Routing RoutingConfig `yaml:"routing"`

	// Proxy is the upstream server this client connects to.
	Proxy ProxyConfig `yaml:"proxy"`
}

// TUNConfig describes the TUN device to create.
type TUNConfig struct {
	// Name is the interface name. Defaults chosen per-platform:
	//   Linux:   tachyon0
	//   macOS:   utun9
	//   Windows: Tachyon
	Name string `yaml:"name"`

	// Address is the IPv4 CIDR assigned to the TUN interface, e.g. "198.18.0.1/16".
	Address string `yaml:"address"`

	// MTU. Defaults to 9000 (jumbo frame) for performance; reduce to 1500 if
	// the network path does not support jumbo frames.
	MTU int `yaml:"mtu"`

	// AutoRoute adds a default route pointing at the TUN interface so all
	// traffic is captured. Disable if using policy routing instead.
	AutoRoute bool `yaml:"auto_route"`

	// DNSHijack intercepts DNS UDP/53 traffic and forwards it through the proxy.
	DNSHijack bool `yaml:"dns_hijack"`
}

// RoutingConfig defines how traffic is classified into routing decisions.
type RoutingConfig struct {
	// DefaultAction is the fallback when no rule matches.
	// One of: "xray", "tgp", "direct", "drop". Defaults to "xray".
	DefaultAction string `yaml:"default_action"`

	// Rules is evaluated in priority order (highest priority first).
	Rules []RouteRule `yaml:"rules"`
}

// RouteRule is a single routing rule. Exactly one match field should be set.
type RouteRule struct {
	// Priority: higher value = evaluated earlier. Defaults to 0.
	Priority int `yaml:"priority"`

	// Match criteria (exactly one should be set):
	ProcessName  string `yaml:"process_name,omitempty"`  // e.g. "cs2.exe"
	Domain       string `yaml:"domain,omitempty"`        // suffix match, e.g. "steam.com"
	CIDR         string `yaml:"cidr,omitempty"`          // e.g. "10.0.0.0/8"
	GeoIPCountry string `yaml:"geoip,omitempty"`         // e.g. "CN"
	Protocol     string `yaml:"protocol,omitempty"`      // "tcp" or "udp"

	// Action to take when matched.
	// One of: "xray", "tgp", "direct", "drop"
	Action string `yaml:"action"`
}

// ProxyConfig describes the upstream Tachyon/Xray server.
type ProxyConfig struct {
	// ServerAddr is the host:port of the remote server, e.g. "vpn.example.com:443".
	ServerAddr string `yaml:"server_addr"`

	// VLESSuuid is the VLESS user ID for Xray traffic.
	VLESSUID string `yaml:"vless_uuid"`

	// TGPServerAddr is the host:port for TGP game traffic.
	// If empty, TGP traffic uses ServerAddr.
	TGPServerAddr string `yaml:"tgp_server_addr,omitempty"`

	// SNI overrides the TLS ServerName for Reality handshake.
	SNI string `yaml:"sni,omitempty"`
}

// ---------------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------------

// ServerConfig holds all server-side settings.
type ServerConfig struct {
	// Listen is the address to bind, e.g. ":443".
	Listen string `yaml:"listen"`

	// TLS configures the server certificate.
	TLS TLSConfig `yaml:"tls"`

	// XrayBackend is the local address where xray-core is listening.
	// tachyon-core (server mode) spawns xray-core and proxies TLS flows to it.
	XrayBackend XrayBackendConfig `yaml:"xray_backend"`

	// Relay configures the UDP relay to upstream game servers.
	Relay RelayConfig `yaml:"relay"`
}

// TLSConfig points at the certificate and key used by the server.
type TLSConfig struct {
	CertFile string `yaml:"cert"`
	KeyFile  string `yaml:"key"`
}

// XrayBackendConfig tells tachyon-core (server) where xray is listening locally.
type XrayBackendConfig struct {
	// Addr is the local TCP address of the xray inbound, e.g. "127.0.0.1:18443".
	Addr string `yaml:"addr"`
}

// RelayConfig controls the UDP relay behaviour.
type RelayConfig struct {
	// DialTimeout is the maximum time to establish an upstream UDP "connection".
	DialTimeout time.Duration `yaml:"dial_timeout"`

	// IdleTimeout closes relay sessions that have been silent for this long.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

// ---------------------------------------------------------------------------
// Shared TGP config
// ---------------------------------------------------------------------------

// TGPConfig holds TGP parameters used by both client and server.
type TGPConfig struct {
	FEC     FECConfig     `yaml:"fec"`
	Pacing  PacingConfig  `yaml:"pacing"`

	// ConnectionMigration enables transparent session migration on IP change.
	ConnectionMigration bool `yaml:"connection_migration"`

	// Multipath enables simultaneous send over all available network interfaces.
	Multipath bool `yaml:"multipath"`

	// HandshakeTimeout is the maximum time to complete the TGP handshake.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`

	// SessionIdleTimeout closes sessions that have been idle for this long.
	SessionIdleTimeout time.Duration `yaml:"session_idle_timeout"`
}

// FECConfig controls Reed-Solomon forward error correction.
type FECConfig struct {
	// DataShards is the number of original data packets per FEC group.
	DataShards int `yaml:"data_shards"`
	// ParityShards is the number of parity packets added per FEC group.
	// Set to 0 to disable FEC.
	ParityShards int `yaml:"parity_shards"`
	// GroupTimeout is how long to wait for all shards before attempting
	// partial reconstruction.
	GroupTimeout time.Duration `yaml:"group_timeout"`
}

// PacingConfig controls the Token Bucket send pacer.
type PacingConfig struct {
	// InitialRatePPS is the starting packet-per-second rate.
	// Auto-adjusted based on measured game tick rate.
	InitialRatePPS float64 `yaml:"initial_rate_pps"`

	// MaxRatePPS is the hard ceiling.
	MaxRatePPS float64 `yaml:"max_rate_pps"`
}

// ---------------------------------------------------------------------------
// Xray binary management
// ---------------------------------------------------------------------------

// XrayConfig controls the xray-core binary lifecycle.
type XrayConfig struct {
	// InstallDir is the directory where tachyon-core stores the xray binary.
	// Defaults to <data_dir>/xray/
	InstallDir string `yaml:"install_dir,omitempty"`

	// ConfigFile is the path to the xray JSON config that tachyon-core generates.
	// Defaults to <data_dir>/xray/config.json
	ConfigFile string `yaml:"config_file,omitempty"`
}

// ---------------------------------------------------------------------------
// IPC (client mode only)
// ---------------------------------------------------------------------------

// IPCConfig controls how Prism connects to Core.
type IPCConfig struct {
	// WebSocketAddr is the address for the real-time telemetry WebSocket.
	WebSocketAddr string `yaml:"websocket_addr"`

	// GRPCAddr is the address for the gRPC control plane.
	GRPCAddr string `yaml:"grpc_addr"`

	// TelemetryIntervalMS controls how frequently telemetry events are pushed.
	TelemetryIntervalMS int `yaml:"telemetry_interval_ms"`
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

// ObservabilityConfig controls logging and metrics.
type ObservabilityConfig struct {
	// LogLevel: "debug", "info", "warn", "error". Defaults to "info".
	LogLevel string `yaml:"log_level"`

	// LogFile writes logs to this path in addition to stderr. Empty = stderr only.
	LogFile string `yaml:"log_file,omitempty"`

	// MetricsAddr is the Prometheus /metrics HTTP endpoint.
	// Empty disables the endpoint.
	MetricsAddr string `yaml:"metrics_addr,omitempty"`
}

// ---------------------------------------------------------------------------
// Load / validate
// ---------------------------------------------------------------------------

// Load reads a YAML config file and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	cfg := defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

// defaults returns a Config populated with sensible defaults.
func defaults() *Config {
	return &Config{
		Mode: ModeClient,
		Client: ClientConfig{
			TUN: TUNConfig{
				Address:   "198.18.0.1/16",
				MTU:       9000,
				AutoRoute: true,
				DNSHijack: true,
			},
			Routing: RoutingConfig{
				DefaultAction: "xray",
			},
		},
		Server: ServerConfig{
			Listen: ":443",
			XrayBackend: XrayBackendConfig{
				Addr: "127.0.0.1:18443",
			},
			Relay: RelayConfig{
				DialTimeout: 5 * time.Second,
				IdleTimeout: 60 * time.Second,
			},
		},
		TGP: TGPConfig{
			FEC: FECConfig{
				DataShards:   4,
				ParityShards: 2,
				GroupTimeout: 20 * time.Millisecond,
			},
			Pacing: PacingConfig{
				InitialRatePPS: 128,
				MaxRatePPS:     1000,
			},
			ConnectionMigration: true,
			Multipath:           false,
			HandshakeTimeout:    5 * time.Second,
			SessionIdleTimeout:  60 * time.Second,
		},
		IPC: IPCConfig{
			WebSocketAddr:       "127.0.0.1:9999",
			GRPCAddr:            "127.0.0.1:50051",
			TelemetryIntervalMS: 500,
		},
		Observability: ObservabilityConfig{
			LogLevel: "info",
		},
	}
}

// Validate checks that the configuration is semantically valid.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeClient, ModeServer:
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeClient, ModeServer, c.Mode)
	}
	if c.Mode == ModeClient {
		if c.Client.Proxy.ServerAddr == "" {
			return fmt.Errorf("client.proxy.server_addr is required in client mode")
		}
	}
	if c.Mode == ModeServer {
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("server.tls.cert and server.tls.key are required in server mode")
		}
	}
	if c.TGP.FEC.DataShards < 1 {
		return fmt.Errorf("tgp.fec.data_shards must be >= 1")
	}
	if c.TGP.Pacing.InitialRatePPS <= 0 {
		return fmt.Errorf("tgp.pacing.initial_rate_pps must be > 0")
	}
	return nil
}
