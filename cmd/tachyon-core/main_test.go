package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightAliasEmitsDoctorJSON(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(configPath, []byte(`{
  "mode": "client",
  "client": {
    "tun": {
      "auto_route": false,
      "dns_hijack": false
    },
    "proxy": {
      "server_addr": "game.example.com:443"
    }
  },
  "tgp": {
    "fec": {
      "data_shards": 4
    },
    "pacing": {
      "initial_rate_pps": 128
    }
  }
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	output := captureStdout(t, func() {
		if err := run([]string{"preflight", "--config", configPath, "--json"}); err != nil {
			t.Fatalf("preflight failed: %v", err)
		}
	})

	var parsed struct {
		OverallStatus string `json:"overall_status"`
		Checks        []struct {
			ID          string `json:"id"`
			Status      string `json:"status"`
			Message     string `json:"message"`
			Remediation string `json:"remediation"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("preflight output is not JSON: %v\n%s", err, output)
	}
	if parsed.OverallStatus == "" {
		t.Fatal("preflight JSON missing overall_status")
	}
	if !hasJSONCheck(parsed.Checks, "CLIENT_REQUIRES_TUN") {
		t.Fatalf("preflight JSON missing CLIENT_REQUIRES_TUN: %#v", parsed.Checks)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = original
	})

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	os.Stdout = original
	return string(data)
}

func hasJSONCheck(checks []struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}, id string) bool {
	for _, check := range checks {
		if check.ID == id {
			return true
		}
	}
	return false
}
