package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadJSONConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	data := []byte(`{
  "mode": "client",
  "client": {
    "proxy": {
      "server_addr": "vpn.example.com:443",
      "vless_uuid": "00000000-0000-0000-0000-000000000000",
      "sni": "vpn.example.com"
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
	if cfg.Client.Proxy.ServerAddr != "vpn.example.com:443" {
		t.Fatalf("server addr = %q", cfg.Client.Proxy.ServerAddr)
	}
	if cfg.TGP.HandshakeTimeout != 5*time.Second {
		t.Fatalf("handshake timeout = %s", cfg.TGP.HandshakeTimeout)
	}
	if cfg.TGP.FEC.GroupTimeout != 20*time.Millisecond {
		t.Fatalf("group timeout = %s", cfg.TGP.FEC.GroupTimeout)
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
