// Package config defines the unified configuration schema for tachyon-core.
//
// A single tachyon-core binary can operate in two modes:
//   - "client"  TUN stack + PID routing + TGP client session
//   - "server"  TGP relay
//
// The mode is selected by the top-level Mode field. Shared subsystems
// (TGP protocol parameters, observability) live at the top level.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/routing"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
	"github.com/tachyon-space/tachyon-core/internal/tun"
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

// Config is the top-level configuration object. JSON is the canonical on-disk
// format; YAML is still accepted so early developer configs keep working.
type Config struct {
	// Mode selects client or server operation. Required.
	Mode Mode `yaml:"mode" json:"mode"`

	// Client contains settings only relevant when Mode == "client".
	Client ClientConfig `yaml:"client,omitempty" json:"client,omitempty"`

	// Server contains settings only relevant when Mode == "server".
	Server ServerConfig `yaml:"server,omitempty" json:"server,omitempty"`

	// TGP contains settings shared between client and server TGP paths.
	TGP TGPConfig `yaml:"tgp" json:"tgp"`

	// IPC controls the Prism-to-Core communication endpoints.
	// Only meaningful in client mode.
	IPC IPCConfig `yaml:"ipc" json:"ipc"`

	// Observability controls logging, metrics and tracing.
	Observability ObservabilityConfig `yaml:"observability" json:"observability"`
}

// ---------------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------------

// ClientConfig holds all client-side settings.
type ClientConfig struct {
	// TUN configures the virtual network interface.
	TUN TUNConfig `yaml:"tun" json:"tun"`

	// Routing defines the rule-based traffic classification engine.
	Routing RoutingConfig `yaml:"routing" json:"routing"`

	// Proxy is the upstream server this client connects to.
	Proxy ProxyConfig `yaml:"proxy" json:"proxy"`
}

// TUNConfig describes the TUN device to create.
type TUNConfig struct {
	// Name is the interface name. Defaults chosen per-platform:
	//   Linux:   tachyon0
	//   macOS:   utun9
	//   Windows: Tachyon
	Name string `yaml:"name" json:"name"`

	// Address is the IPv4 CIDR assigned to the TUN interface, e.g. "198.18.0.1/16".
	Address string `yaml:"address" json:"address"`

	// MTU defaults to the IPv6 minimum of 1280. The matching default TGP budget
	// leaves headroom below a 1400-byte outer path.
	MTU int `yaml:"mtu" json:"mtu"`

	// AutoRoute would add a default route pointing at the TUN interface. It must
	// remain false until Core implements a native direct forwarding path.
	AutoRoute bool `yaml:"auto_route" json:"auto_route"`

	// DNSHijack is reserved for a future native DNS forwarding path and currently
	// fails client config validation when enabled.
	DNSHijack bool `yaml:"dns_hijack" json:"dns_hijack"`

	// TGPOnly rejects captured direct traffic instead of silently consuming it.
	// It must remain enabled; OS integration owns selective route installation.
	TGPOnly bool `yaml:"tgp_only" json:"tgp_only"`
}

// RoutingConfig defines how traffic is classified into routing decisions.
type RoutingConfig struct {
	// DefaultAction is the fallback when no rule matches.
	// One of: "direct", "drop", "block". Defaults to "direct". TGP requires
	// an explicitly UDP-matched rule or game profile.
	DefaultAction string `yaml:"default_action" json:"default_action"`

	// Rules is evaluated in priority order (highest priority first).
	Rules []RouteRule `yaml:"rules" json:"rules"`

	// GameProfiles are Prism-managed process/application profiles used before
	// generic route rules.
	GameProfiles []routing.GameProfile `yaml:"game_profiles,omitempty" json:"game_profiles,omitempty"`

	// Launchers controls well-known launcher heuristics, such as Steam child
	// process detection. If omitted, routing package defaults are used.
	Launchers *routing.LauncherPolicy `yaml:"launchers,omitempty" json:"launchers,omitempty"`
}

// RouteRule is a single routing rule. Exactly one match field should be set.
type RouteRule struct {
	// Priority: higher value = evaluated earlier. Defaults to 0.
	Priority int `yaml:"priority" json:"priority"`

	// Match criteria (exactly one should be set):
	ProcessName  string `yaml:"process_name,omitempty" json:"process_name,omitempty"` // e.g. "cs2.exe"
	Domain       string `yaml:"domain,omitempty" json:"domain,omitempty"`             // suffix match, e.g. "steam.com"
	CIDR         string `yaml:"cidr,omitempty" json:"cidr,omitempty"`                 // e.g. "10.0.0.0/8"
	GeoIPCountry string `yaml:"geoip,omitempty" json:"geoip,omitempty"`               // e.g. "CN"
	Protocol     string `yaml:"protocol,omitempty" json:"protocol,omitempty"`         // "tcp" or "udp"

	// Action to take when matched.
	// One of: "tgp", "direct", "drop", "block".
	Action string `yaml:"action" json:"action"`
}

// ProxyConfig describes the upstream Tachyon TGP server.
type ProxyConfig struct {
	// ServerAddr is the host:port of the remote TGP server, e.g. "game.example.com:443".
	ServerAddr string `yaml:"server_addr" json:"server_addr"`

	// TGPServerAddr is the host:port for TGP game traffic.
	// If empty, TGP traffic uses ServerAddr.
	TGPServerAddr string `yaml:"tgp_server_addr,omitempty" json:"tgp_server_addr,omitempty"`

	// LocalAddrs optionally pins client-side UDP bind addresses for multipath,
	// e.g. ["192.168.1.10:0", "10.0.0.5:0"]. Empty uses "0.0.0.0:0".
	LocalAddrs []string `yaml:"local_addrs,omitempty" json:"local_addrs,omitempty"`
}

// ---------------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------------

// ServerConfig holds all server-side settings.
type ServerConfig struct {
	// Listen is the address to bind, e.g. ":443".
	Listen string `yaml:"listen" json:"listen"`

	// TLS configures the server certificate.
	TLS TLSConfig `yaml:"tls" json:"tls"`

	// Relay configures the UDP relay to upstream game servers.
	Relay RelayConfig `yaml:"relay" json:"relay"`
}

// TLSConfig points at the certificate and key used by the server.
type TLSConfig struct {
	CertFile string `yaml:"cert" json:"cert"`
	KeyFile  string `yaml:"key" json:"key"`
}

// RelayConfig controls the UDP relay behaviour.
type RelayConfig struct {
	// DialTimeout is the maximum time to establish an upstream UDP "connection".
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`

	// IdleTimeout closes relay sessions that have been silent for this long.
	IdleTimeout time.Duration `yaml:"idle_timeout" json:"idle_timeout"`

	// MaxSessions caps concurrently established TGP sessions.
	MaxSessions int `yaml:"max_sessions" json:"max_sessions"`

	// SessionQueueSize caps queued packets per TGP session while the relay
	// demux path fans encrypted packets out to sessions.
	SessionQueueSize int `yaml:"session_queue_size" json:"session_queue_size"`

	// HandlerConcurrency caps concurrent relay handler goroutines.
	HandlerConcurrency int `yaml:"handler_concurrency" json:"handler_concurrency"`

	// MaxFlows caps total UDP relay flows across all sessions.
	MaxFlows int `yaml:"max_flows" json:"max_flows"`

	// MaxFlowsPerSession caps UDP relay flows owned by a single TGP session.
	MaxFlowsPerSession int `yaml:"max_flows_per_session" json:"max_flows_per_session"`

	// AllowedTargets is an explicit allow-list for UDP relay targets. Empty
	// means deny all targets; loopback/private/reserved ranges also require an
	// explicit rule.
	AllowedTargets []RelayTargetRule `yaml:"allowed_targets,omitempty" json:"allowed_targets,omitempty"`
}

type RelayTargetRule struct {
	CIDR   string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
	Ports  string `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// ---------------------------------------------------------------------------
// Shared TGP config
// ---------------------------------------------------------------------------

// TGPConfig holds TGP parameters used by both client and server.
type TGPConfig struct {
	FEC    FECConfig     `yaml:"fec" json:"fec"`
	Pacing PacingConfig  `yaml:"pacing" json:"pacing"`
	Auth   TGPAuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`

	// ConnectionMigration enables transparent session migration on IP change.
	ConnectionMigration bool `yaml:"connection_migration" json:"connection_migration"`

	// Multipath enables simultaneous send over all available network interfaces.
	Multipath bool `yaml:"multipath" json:"multipath"`

	// MaxDatagramSize caps the complete encrypted TGP UDP payload.
	MaxDatagramSize int `yaml:"max_datagram_size" json:"max_datagram_size"`

	// HandshakeTimeout is the maximum time to complete the TGP handshake.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout" json:"handshake_timeout"`

	// SessionIdleTimeout closes sessions that have been idle for this long.
	SessionIdleTimeout time.Duration `yaml:"session_idle_timeout" json:"session_idle_timeout"`
}

const placeholderTGPPSK = "replace-with-shared-tgp-psk"

// TGPAuthConfig controls pre-shared-key authentication for TGP handshakes.
// Server mode requires PSK unless AllowUnauthenticated is explicitly enabled
// for local development or alpha compatibility testing.
type TGPAuthConfig struct {
	PSK                  string `yaml:"psk,omitempty" json:"psk,omitempty"`
	AllowUnauthenticated bool   `yaml:"allow_unauthenticated,omitempty" json:"allow_unauthenticated,omitempty"`
}

// FECConfig controls Reed-Solomon forward error correction.
type FECConfig struct {
	// DataShards is the number of original data packets per FEC group.
	DataShards int `yaml:"data_shards" json:"data_shards"`
	// ParityShards is the number of parity packets added per FEC group.
	// Set to 0 to disable FEC.
	ParityShards int `yaml:"parity_shards" json:"parity_shards"`
	// GroupTimeout is how long to wait for all shards before attempting
	// partial reconstruction.
	GroupTimeout time.Duration `yaml:"group_timeout" json:"group_timeout"`
	// Dynamic lets Core adjust parity based on observed FEC recovery ratio.
	Dynamic bool `yaml:"dynamic" json:"dynamic"`
	// AdaptWindow is the number of delivered payloads in one adjustment window.
	AdaptWindow int `yaml:"adapt_window" json:"adapt_window"`
}

// PacingConfig controls the Token Bucket send pacer.
type PacingConfig struct {
	// InitialRatePPS is the starting packet-per-second rate.
	// Auto-adjusted based on measured game tick rate.
	InitialRatePPS float64 `yaml:"initial_rate_pps" json:"initial_rate_pps"`

	// MaxRatePPS is the hard ceiling.
	MaxRatePPS float64 `yaml:"max_rate_pps" json:"max_rate_pps"`
}

// ---------------------------------------------------------------------------
// IPC (client mode only)
// ---------------------------------------------------------------------------

// IPCConfig controls how Prism connects to Core.
type IPCConfig struct {
	// WebSocketAddr is the address for the real-time telemetry WebSocket.
	WebSocketAddr string `yaml:"websocket_addr" json:"websocket_addr"`

	// GRPCAddr is the address for the gRPC control plane.
	GRPCAddr string `yaml:"grpc_addr" json:"grpc_addr"`

	// TelemetryIntervalMS controls how frequently telemetry events are pushed.
	TelemetryIntervalMS int `yaml:"telemetry_interval_ms" json:"telemetry_interval_ms"`
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

// ObservabilityConfig controls logging and metrics.
type ObservabilityConfig struct {
	// LogLevel: "debug", "info", "warn", "error". Defaults to "info".
	LogLevel string `yaml:"log_level" json:"log_level"`

	// LogFile writes logs to this path in addition to stderr. Empty = stderr only.
	LogFile string `yaml:"log_file,omitempty" json:"log_file,omitempty"`

	// MetricsAddr is the Prometheus /metrics HTTP endpoint.
	// Empty disables the endpoint.
	MetricsAddr string `yaml:"metrics_addr,omitempty" json:"metrics_addr,omitempty"`
}

// ---------------------------------------------------------------------------
// Load / validate
// ---------------------------------------------------------------------------

// Load reads a JSON config file and applies defaults. Legacy YAML files are
// accepted for now, but generated configs use JSON.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	cfg := defaults()
	if err := unmarshalConfig(path, data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	resolveRelativePaths(path, cfg)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func unmarshalConfig(path string, data []byte, cfg *Config) error {
	trimmed := bytes.TrimSpace(data)
	if isJSONConfig(path, trimmed) && !json.Valid(trimmed) {
		return fmt.Errorf("invalid JSON")
	}
	return yaml.Unmarshal(data, cfg)
}

func isJSONConfig(path string, data []byte) bool {
	if strings.EqualFold(filepath.Ext(path), ".json") {
		return true
	}
	return bytes.HasPrefix(data, []byte("{"))
}

func resolveRelativePaths(configPath string, cfg *Config) {
	baseDir := filepath.Dir(configPath)
	if absPath, err := filepath.Abs(configPath); err == nil {
		baseDir = filepath.Dir(absPath)
	}

	cfg.Server.TLS.CertFile = resolvePath(baseDir, cfg.Server.TLS.CertFile)
	cfg.Server.TLS.KeyFile = resolvePath(baseDir, cfg.Server.TLS.KeyFile)
	cfg.Observability.LogFile = resolvePath(baseDir, cfg.Observability.LogFile)
}

func resolvePath(baseDir string, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}

// defaults returns a Config populated with sensible defaults.
func defaults() *Config {
	return &Config{
		Mode: ModeClient,
		Client: ClientConfig{
			TUN: TUNConfig{
				Address:   "198.18.0.1/16",
				MTU:       tun.DefaultMTU,
				AutoRoute: false,
				DNSHijack: false,
				TGPOnly:   true,
			},
			Routing: RoutingConfig{
				DefaultAction: "direct",
			},
		},
		Server: ServerConfig{
			Listen: ":443",
			Relay: RelayConfig{
				DialTimeout:        5 * time.Second,
				IdleTimeout:        60 * time.Second,
				MaxSessions:        1024,
				SessionQueueSize:   256,
				HandlerConcurrency: 1024,
				MaxFlows:           4096,
				MaxFlowsPerSession: 256,
			},
		},
		TGP: TGPConfig{
			FEC: FECConfig{
				DataShards:   4,
				ParityShards: 2,
				GroupTimeout: 20 * time.Millisecond,
				Dynamic:      true,
				AdaptWindow:  32,
			},
			Pacing: PacingConfig{
				InitialRatePPS: 128,
				MaxRatePPS:     1000,
			},
			ConnectionMigration: true,
			Multipath:           false,
			MaxDatagramSize:     tgp.DefaultTGPDatagramSize,
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
	maxDatagramSize := c.TGP.MaxDatagramSize
	if maxDatagramSize == 0 {
		maxDatagramSize = tgp.DefaultTGPDatagramSize
	}
	if maxDatagramSize < tgp.MinTGPDatagramSize || maxDatagramSize > tgp.MaxTGPDatagramSize {
		return fmt.Errorf("tgp.max_datagram_size %d must be between %d and %d", maxDatagramSize, tgp.MinTGPDatagramSize, tgp.MaxTGPDatagramSize)
	}
	if c.Mode == ModeClient {
		if c.Client.Proxy.ServerAddr == "" {
			return fmt.Errorf("client.proxy.server_addr is required in client mode")
		}
		if err := validateLocalAddrs(c.Client.Proxy.LocalAddrs); err != nil {
			return err
		}
		if c.TGP.Multipath && countLocalAddrs(c.Client.Proxy.LocalAddrs) < 2 {
			return fmt.Errorf("tgp.multipath requires at least two client.proxy.local_addrs entries")
		}
		if c.TGP.Multipath && !c.TGP.ConnectionMigration {
			return fmt.Errorf("tgp.multipath requires tgp.connection_migration")
		}
		if err := validateGameProfiles(c.Client.Routing.GameProfiles); err != nil {
			return err
		}
		if err := validateClientDataPath(c.Client); err != nil {
			return err
		}
		tunMTU := c.Client.TUN.MTU
		if tunMTU == 0 {
			tunMTU = tun.DefaultMTU
		}
		if tunMTU < 576 {
			return fmt.Errorf("client.tun.mtu must be at least 576")
		}
		if required := tunMTU + tgp.WorstCaseTUNOverhead; required > maxDatagramSize {
			return fmt.Errorf("client.tun.mtu %d requires tgp.max_datagram_size >= %d, configured %d; lower the TUN MTU or raise the path budget", tunMTU, required, maxDatagramSize)
		}
	}
	if c.Mode == ModeServer {
		if c.Server.Listen == "" {
			return fmt.Errorf("server.listen is required in server mode")
		}
		if err := validateRelayTargets(c.Server.Relay.AllowedTargets); err != nil {
			return err
		}
		if err := validateRelayLimits(c.Server.Relay); err != nil {
			return err
		}
	}
	if c.TGP.FEC.DataShards < 1 {
		return fmt.Errorf("tgp.fec.data_shards must be >= 1")
	}
	if c.TGP.FEC.DataShards > tgp.MaxFECDataShards {
		return fmt.Errorf("tgp.fec.data_shards must be <= %d", tgp.MaxFECDataShards)
	}
	if c.TGP.FEC.ParityShards < 0 || c.TGP.FEC.ParityShards > tgp.MaxFECParityShards {
		return fmt.Errorf("tgp.fec.parity_shards must be between 0 and %d", tgp.MaxFECParityShards)
	}
	if c.TGP.FEC.DataShards+c.TGP.FEC.ParityShards > tgp.MaxFECTotalShards {
		return fmt.Errorf("tgp.fec total shards must be <= %d", tgp.MaxFECTotalShards)
	}
	if c.TGP.Pacing.InitialRatePPS <= 0 {
		return fmt.Errorf("tgp.pacing.initial_rate_pps must be > 0")
	}
	if c.TGP.Pacing.MaxRatePPS < 0 {
		return fmt.Errorf("tgp.pacing.max_rate_pps must be >= 0")
	}
	psk := strings.TrimSpace(c.TGP.Auth.PSK)
	if strings.EqualFold(psk, placeholderTGPPSK) {
		return fmt.Errorf("tgp.auth.psk must be replaced with a unique secret")
	}
	if psk != "" && len(psk) < 16 {
		return fmt.Errorf("tgp.auth.psk must be at least 16 characters when set")
	}
	if c.Mode == ModeServer && psk == "" && !c.TGP.Auth.AllowUnauthenticated {
		return fmt.Errorf("server mode requires tgp.auth.psk unless tgp.auth.allow_unauthenticated is true")
	}
	return nil
}

func validateClientDataPath(cfg ClientConfig) error {
	if cfg.TUN.AutoRoute {
		return fmt.Errorf("client.tun.auto_route=true is not supported until Core has a native direct forwarding path; use OS-level selective routes for TGP game traffic")
	}
	if cfg.TUN.DNSHijack {
		return fmt.Errorf("client.tun.dns_hijack=true is not supported by the Core-only TGP data path")
	}
	if !cfg.TUN.TGPOnly {
		return fmt.Errorf("client.tun.tgp_only must be true because captured direct traffic cannot be forwarded safely")
	}
	return validateRoutingConfig(cfg.Routing)
}

func validateRoutingConfig(cfg RoutingConfig) error {
	if action := strings.TrimSpace(cfg.DefaultAction); action != "" {
		if !isRouteAction(action) {
			return fmt.Errorf("client.routing.default_action %q must be tgp, direct, drop, or block", cfg.DefaultAction)
		}
		if strings.EqualFold(action, "tgp") {
			return fmt.Errorf("client.routing.default_action cannot be tgp because TGP only forwards explicitly UDP-matched rules and game profiles")
		}
	}
	for idx, rule := range cfg.Rules {
		if strings.TrimSpace(rule.Domain) != "" {
			return fmt.Errorf("client.routing.rules[%d].domain is not implemented by the Core-only packet path", idx)
		}
		if strings.TrimSpace(rule.GeoIPCountry) != "" {
			return fmt.Errorf("client.routing.rules[%d].geoip is not implemented by the Core-only packet path", idx)
		}
		if strings.TrimSpace(rule.ProcessName) == "" && strings.TrimSpace(rule.CIDR) == "" && strings.TrimSpace(rule.Protocol) == "" {
			return fmt.Errorf("client.routing.rules[%d] requires process_name, cidr, or protocol", idx)
		}
		if value := strings.TrimSpace(rule.CIDR); value != "" {
			if _, err := netip.ParsePrefix(value); err != nil {
				return fmt.Errorf("client.routing.rules[%d].cidr %q is invalid: %w", idx, rule.CIDR, err)
			}
		}
		protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
		if protocol != "" && protocol != "udp" && protocol != "tcp" {
			return fmt.Errorf("client.routing.rules[%d].protocol %q must be tcp or udp", idx, rule.Protocol)
		}
		if !isRouteAction(rule.Action) {
			return fmt.Errorf("client.routing.rules[%d].action %q must be tgp, direct, drop, or block", idx, rule.Action)
		}
		if strings.EqualFold(strings.TrimSpace(rule.Action), "tgp") && protocol != "udp" {
			return fmt.Errorf("client.routing.rules[%d] with action tgp must set protocol to udp", idx)
		}
	}
	return nil
}

func isRouteAction(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tgp", "direct", "drop", "block":
		return true
	default:
		return false
	}
}

func validateRelayTargets(rules []RelayTargetRule) error {
	for idx, rule := range rules {
		if strings.TrimSpace(rule.CIDR) == "" && strings.TrimSpace(rule.Domain) == "" {
			return fmt.Errorf("server.relay.allowed_targets[%d] requires cidr or domain", idx)
		}
		if value := strings.TrimSpace(rule.CIDR); value != "" {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return fmt.Errorf("server.relay.allowed_targets[%d].cidr %q is invalid: %w", idx, rule.CIDR, err)
			}
			if prefix.Bits() == 0 {
				return fmt.Errorf("server.relay.allowed_targets[%d].cidr must not allow the whole internet", idx)
			}
		}
		if value := strings.TrimSpace(rule.Domain); value != "" && strings.Contains(value, ":") {
			return fmt.Errorf("server.relay.allowed_targets[%d].domain must not include a port", idx)
		}
		if strings.TrimSpace(rule.Ports) == "" {
			return fmt.Errorf("server.relay.allowed_targets[%d].ports is required", idx)
		}
		if err := validatePortRanges(rule.Ports); err != nil {
			return fmt.Errorf("server.relay.allowed_targets[%d].ports: %w", idx, err)
		}
	}
	return nil
}

func validateRelayLimits(cfg RelayConfig) error {
	if cfg.MaxSessions < 0 {
		return fmt.Errorf("server.relay.max_sessions must be >= 0")
	}
	if cfg.SessionQueueSize < 0 {
		return fmt.Errorf("server.relay.session_queue_size must be >= 0")
	}
	if cfg.HandlerConcurrency < 0 {
		return fmt.Errorf("server.relay.handler_concurrency must be >= 0")
	}
	if cfg.MaxFlows < 0 {
		return fmt.Errorf("server.relay.max_flows must be >= 0")
	}
	if cfg.MaxFlowsPerSession < 0 {
		return fmt.Errorf("server.relay.max_flows_per_session must be >= 0")
	}
	return nil
}

func validatePortRanges(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	for _, part := range strings.Split(value, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			return fmt.Errorf("empty port range")
		}
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 {
			return fmt.Errorf("invalid range %q", item)
		}
		start, err := parsePortNumber(bounds[0])
		if err != nil {
			return err
		}
		end := start
		if len(bounds) == 2 {
			end, err = parsePortNumber(bounds[1])
			if err != nil {
				return err
			}
		}
		if start > end {
			return fmt.Errorf("range %q has start greater than end", item)
		}
	}
	return nil
}

func parsePortNumber(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid UDP port %q", raw)
	}
	return port, nil
}

func countLocalAddrs(addrs []string) int {
	count := 0
	for _, addr := range addrs {
		if strings.TrimSpace(addr) != "" {
			count++
		}
	}
	return count
}

func validateLocalAddrs(addrs []string) error {
	for idx, addr := range addrs {
		value := strings.TrimSpace(addr)
		if value == "" {
			return fmt.Errorf("client.proxy.local_addrs[%d] must not be empty", idx)
		}
		if _, err := net.ResolveUDPAddr("udp", value); err != nil {
			return fmt.Errorf("client.proxy.local_addrs[%d] %q is not a valid UDP address: %w", idx, addr, err)
		}
	}
	return nil
}

func validateGameProfiles(profiles []routing.GameProfile) error {
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if err := routing.ValidateProfile(profile); err != nil {
			return fmt.Errorf("client.routing.game_profiles: %w", err)
		}
		key := strings.ToLower(strings.TrimSpace(profile.ID))
		if _, ok := seen[key]; ok {
			return fmt.Errorf("client.routing.game_profiles: duplicate id %q", profile.ID)
		}
		seen[key] = struct{}{}
	}
	return nil
}
