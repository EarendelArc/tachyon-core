package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/routing"
)

func TestLoadJSONConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	data := []byte(`{
  "mode": "client",
  "client": {
    "proxy": {
      "server_addr": "game.example.com:443",
      "local_addrs": ["127.0.0.1:0", "127.0.0.2:0"]
    }
  },
  "tgp": {
    "fec": {
      "data_shards": 4,
      "parity_shards": 2,
      "group_timeout": "20ms"
    },
    "pacing": {
      "initial_rate_pps": 128,
      "max_rate_pps": 1000
    },
    "handshake_timeout": "5s"
  }
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load json config: %v", err)
	}
	if cfg.Mode != ModeClient {
		t.Fatalf("mode = %q, want %q", cfg.Mode, ModeClient)
	}
	if cfg.Client.Proxy.ServerAddr != "game.example.com:443" {
		t.Fatalf("server addr = %q", cfg.Client.Proxy.ServerAddr)
	}
	if got := cfg.Client.Proxy.LocalAddrs; len(got) != 2 || got[0] != "127.0.0.1:0" || got[1] != "127.0.0.2:0" {
		t.Fatalf("local addrs = %#v", got)
	}
	if cfg.TGP.HandshakeTimeout != 5*time.Second {
		t.Fatalf("handshake timeout = %s", cfg.TGP.HandshakeTimeout)
	}
	if cfg.TGP.FEC.GroupTimeout != 20*time.Millisecond {
		t.Fatalf("group timeout = %s", cfg.TGP.FEC.GroupTimeout)
	}
	if !cfg.TGP.FEC.Dynamic {
		t.Fatal("expected dynamic FEC to default to enabled")
	}
	if cfg.TGP.FEC.AdaptWindow != 32 {
		t.Fatalf("adapt window = %d, want 32", cfg.TGP.FEC.AdaptWindow)
	}
	if cfg.Client.TUN.AutoRoute {
		t.Fatal("client.tun.auto_route should default to false in TGP-only mode")
	}
	if cfg.Client.TUN.DNSHijack {
		t.Fatal("client.tun.dns_hijack should default to false in TGP-only mode")
	}
	if !cfg.Client.TUN.TGPOnly {
		t.Fatal("client.tun.tgp_only should default to true")
	}
}

func TestLoadJSONRejectsYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte("mode: client\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestLoadEmbeddedGameProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	data := []byte(`{
  "mode": "client",
  "client": {
    "routing": {
      "default_action": "direct",
      "game_profiles": [
        {
          "id": "manual-cs2",
          "displayName": "Counter-Strike 2",
          "enabled": true,
          "manual": true,
          "priority": 100,
          "match": {
            "processNames": ["cs2.exe"],
            "paths": [],
            "pathPrefixes": [],
            "sha256": [],
            "steamAppIds": [730]
          },
          "udpPolicy": "tgp",
          "tcpPolicy": "auto"
        }
      ],
      "launchers": {
        "steam": {
          "enabled": true,
          "trackChildProcesses": true,
          "accelerateGameUdp": true,
          "accelerateSteamDownloads": false
        }
      }
    },
    "proxy": {
      "server_addr": "game.example.com:443"
    }
  }
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got := len(cfg.Client.Routing.GameProfiles); got != 1 {
		t.Fatalf("game profiles = %d, want 1", got)
	}
	if cfg.Client.Routing.GameProfiles[0].Match.ProcessNames[0] != "cs2.exe" {
		t.Fatalf("unexpected profile: %#v", cfg.Client.Routing.GameProfiles[0])
	}
	if cfg.Client.Routing.Launchers == nil || !cfg.Client.Routing.Launchers.Steam.Enabled {
		t.Fatalf("steam launcher policy not loaded: %#v", cfg.Client.Routing.Launchers)
	}
}

func TestLoadLegacyYAMLConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	data := []byte(`mode: client
client:
  proxy:
    server_addr: vpn.example.com:443
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load legacy yaml config: %v", err)
	}
	if cfg.Client.Proxy.ServerAddr != "vpn.example.com:443" {
		t.Fatalf("server addr = %q", cfg.Client.Proxy.ServerAddr)
	}
}

func TestLoadResolvesRelativePathsFromConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	data := []byte(`{
  "mode": "client",
  "client": {
    "proxy": {
      "server_addr": "game.example.com:443"
    }
  },
  "observability": {
    "log_file": "logs/tachyon.log"
  }
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	assertPath(t, cfg.Observability.LogFile, filepath.Join(dir, "logs", "tachyon.log"))
}

func TestLoadKeepsAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	certPath := filepath.Join(dir, "certs", "fullchain.pem")
	keyPath := filepath.Join(dir, "certs", "key.pem")
	data := []byte(`{
  "mode": "server",
  "server": {
    "tls": {
      "cert": ` + quoteJSON(certPath) + `,
      "key": ` + quoteJSON(keyPath) + `
    }
  },
  "tgp": {
    "auth": {
      "psk": "0123456789abcdef"
    }
  }
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	assertPath(t, cfg.Server.TLS.CertFile, certPath)
	assertPath(t, cfg.Server.TLS.KeyFile, keyPath)
}

func assertPath(t *testing.T, got string, want string) {
	t.Helper()
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func quoteJSON(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestValidateClientRequiresProxyServerAddr(t *testing.T) {
	cfg := Config{
		Mode: ModeClient,
		Client: ClientConfig{
			Proxy: ProxyConfig{},
		},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing server_addr")
	}
}

func TestValidateServerRequiresListen(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing server.listen")
	}
}

func TestValidateRejectsInvalidMode(t *testing.T) {
	cfg := Config{
		Mode: "unknown",
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestValidateRejectsInsufficientDataShards(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{Listen: ":443"},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 0},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for zero data_shards")
	}
}

func TestValidateRejectsZeroInitialRatePPS(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{Listen: ":443"},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 0},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for zero initial_rate_pps")
	}
}

func TestValidateRejectsNegativeMaxRatePPS(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{Listen: ":443"},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128, MaxRatePPS: -1},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative max_rate_pps")
	}
}

func TestValidateRejectsShortTGPAuthPSK(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{Listen: ":443"},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
			Auth:   TGPAuthConfig{PSK: "too-short"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for short tgp.auth.psk")
	}

	cfg.TGP.Auth.PSK = "0123456789abcdef"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid psk, got error: %v", err)
	}
}

func TestValidateRejectsPlaceholderTGPAuthPSK(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{Listen: ":443"},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
			Auth:   TGPAuthConfig{PSK: placeholderTGPPSK},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for placeholder tgp.auth.psk")
	}
}

func TestValidateClientWithProfilesAndServerAddr(t *testing.T) {
	cfg := Config{
		Mode: ModeClient,
		Client: ClientConfig{
			Proxy: ProxyConfig{ServerAddr: "game.example.com:443"},
			Routing: RoutingConfig{
				GameProfiles: []routing.GameProfile{
					{
						ID:          "test",
						DisplayName: "Test",
						Match:       routing.MatchRule{ProcessNames: []string{"test.exe"}},
					},
				},
			},
		},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestValidateRejectsInvalidClientLocalAddr(t *testing.T) {
	cfg := Config{
		Mode: ModeClient,
		Client: ClientConfig{
			Proxy: ProxyConfig{
				ServerAddr: "game.example.com:443",
				LocalAddrs: []string{
					"not a udp addr",
				},
			},
		},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid local_addrs error")
	}
}

func TestValidateRequiresTwoLocalAddrsForMultipath(t *testing.T) {
	cfg := Config{
		Mode: ModeClient,
		Client: ClientConfig{
			Proxy: ProxyConfig{
				ServerAddr: "game.example.com:443",
				LocalAddrs: []string{
					"127.0.0.1:0",
				},
			},
		},
		TGP: TGPConfig{
			FEC:                 FECConfig{DataShards: 4},
			Pacing:              PacingConfig{InitialRatePPS: 128},
			ConnectionMigration: true,
			Multipath:           true,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected multipath local_addrs error")
	}

	cfg.Client.Proxy.LocalAddrs = append(cfg.Client.Proxy.LocalAddrs, "127.0.0.2:0")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid multipath config, got error: %v", err)
	}
}

func TestValidateRejectsMultipathWithoutConnectionMigration(t *testing.T) {
	cfg := Config{
		Mode: ModeClient,
		Client: ClientConfig{
			Proxy: ProxyConfig{
				ServerAddr: "game.example.com:443",
				LocalAddrs: []string{
					"127.0.0.1:0",
					"127.0.0.2:0",
				},
			},
		},
		TGP: TGPConfig{
			FEC:                 FECConfig{DataShards: 4},
			Pacing:              PacingConfig{InitialRatePPS: 128},
			ConnectionMigration: false,
			Multipath:           true,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected multipath connection_migration error")
	}

	cfg.TGP.ConnectionMigration = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid multipath config, got error: %v", err)
	}
}

func TestValidateServerWithListen(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{Listen: ":443"},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
			Auth:   TGPAuthConfig{PSK: "0123456789abcdef"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid server config, got error: %v", err)
	}
}

func TestValidateServerRelayAllowedTargets(t *testing.T) {
	cfg := Config{
		Mode: ModeServer,
		Server: ServerConfig{
			Listen: ":443",
			Relay: RelayConfig{
				AllowedTargets: []RelayTargetRule{
					{CIDR: "203.0.113.0/24", Ports: "27015-27016,27020"},
					{Domain: "example.com", Ports: "443"},
				},
			},
		},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
			Auth:   TGPAuthConfig{PSK: "0123456789abcdef"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid relay targets, got: %v", err)
	}

	cfg.Server.Relay.AllowedTargets = []RelayTargetRule{{CIDR: "not-cidr"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid CIDR error")
	}

	cfg.Server.Relay.AllowedTargets = []RelayTargetRule{{CIDR: "0.0.0.0/0", Ports: "27015"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected wildcard IPv4 CIDR error")
	}

	cfg.Server.Relay.AllowedTargets = []RelayTargetRule{{CIDR: "::/0", Ports: "27015"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected wildcard IPv6 CIDR error")
	}

	cfg.Server.Relay.AllowedTargets = []RelayTargetRule{{CIDR: "203.0.113.0/24"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing ports error")
	}

	cfg.Server.Relay.AllowedTargets = []RelayTargetRule{{CIDR: "203.0.113.0/24", Ports: "27016-27015"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid port range error")
	}
}

func TestValidateServerRelayLimits(t *testing.T) {
	cfg := Config{
		Mode: ModeServer,
		Server: ServerConfig{
			Listen: ":443",
			Relay: RelayConfig{
				MaxSessions:        1,
				SessionQueueSize:   1,
				HandlerConcurrency: 1,
				MaxFlows:           1,
				MaxFlowsPerSession: 1,
			},
		},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
			Auth:   TGPAuthConfig{PSK: "0123456789abcdef"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid relay limits, got: %v", err)
	}

	cfg.Server.Relay.MaxSessions = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected negative max_sessions error")
	}
}

func TestValidateServerRequiresAuthByDefault(t *testing.T) {
	cfg := Config{
		Mode:   ModeServer,
		Server: ServerConfig{Listen: ":443"},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected server mode to require tgp.auth.psk")
	}

	cfg.TGP.Auth.AllowUnauthenticated = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected explicit unauthenticated server config to validate, got: %v", err)
	}
}

func TestValidateClientDuplicateProfileIDs(t *testing.T) {
	cfg := Config{
		Mode: ModeClient,
		Client: ClientConfig{
			Proxy: ProxyConfig{ServerAddr: "game.example.com:443"},
			Routing: RoutingConfig{
				GameProfiles: []routing.GameProfile{
					{ID: "dup", DisplayName: "A", Match: routing.MatchRule{ProcessNames: []string{"a.exe"}}},
					{ID: "DUP", DisplayName: "B", Match: routing.MatchRule{ProcessNames: []string{"b.exe"}}},
				},
			},
		},
		TGP: TGPConfig{
			FEC:    FECConfig{DataShards: 4},
			Pacing: PacingConfig{InitialRatePPS: 128},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate profile IDs")
	}
}
