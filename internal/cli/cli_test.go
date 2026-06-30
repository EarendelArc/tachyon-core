package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/config"
)

func TestGenerateConfigClient(t *testing.T) {
	rendered, err := GenerateConfig(config.ModeClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rendered == "" {
		t.Fatal("empty client template")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("client template is not valid JSON: %v", err)
	}

	mode, _ := parsed["mode"].(string)
	if mode != "client" {
		t.Fatalf("expected mode client, got %q", mode)
	}

	client, ok := parsed["client"].(map[string]any)
	if !ok {
		t.Fatal("missing client section")
	}
	if _, ok := client["tun"]; !ok {
		t.Fatal("missing client.tun")
	}
	if _, ok := client["routing"]; !ok {
		t.Fatal("missing client.routing")
	}
	tun, ok := client["tun"].(map[string]any)
	if !ok {
		t.Fatal("client.tun must be an object")
	}
	if tun["auto_route"] != false {
		t.Fatalf("client template should default auto_route to false, got %#v", tun["auto_route"])
	}
	if tun["dns_hijack"] != false {
		t.Fatalf("client template should default dns_hijack to false, got %#v", tun["dns_hijack"])
	}
}

func TestGenerateConfigServer(t *testing.T) {
	rendered, err := GenerateConfig(config.ModeServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("server template is not valid JSON: %v", err)
	}

	mode, _ := parsed["mode"].(string)
	if mode != "server" {
		t.Fatalf("expected mode server, got %q", mode)
	}

	if _, ok := parsed["server"]; !ok {
		t.Fatal("missing server section")
	}
}

func TestGenerateConfigUnknownMode(t *testing.T) {
	_, err := GenerateConfig("invalid")
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestValidateConfigValidClient(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	writeFile(t, path, `{"mode":"client","client":{"tun":{"name":"","address":"198.18.0.1/16","mtu":9000,"auto_route":true,"dns_hijack":true},"routing":{"default_action":"direct","game_profiles":[],"rules":[]},"proxy":{"server_addr":"example.com:443","tgp_server_addr":"example.com:443"}},"tgp":{"fec":{"data_shards":4,"parity_shards":2},"connection_migration":true},"ipc":{"websocket_addr":"127.0.0.1:55123"},"observability":{"log_level":"info"}}`)

	mode, err := ValidateConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != config.ModeClient {
		t.Fatalf("expected client mode, got %q", mode)
	}
}

func TestValidateConfigValidServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	writeFile(t, path, `{"mode":"server","server":{"listen":":443"},"tgp":{"fec":{"data_shards":4,"parity_shards":2},"connection_migration":true},"observability":{"log_level":"info"}}`)

	mode, err := ValidateConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != config.ModeServer {
		t.Fatalf("expected server mode, got %q", mode)
	}
}

func TestValidateConfigMissing(t *testing.T) {
	_, err := ValidateConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestValidateConfigInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	writeFile(t, path, `not json`)

	_, err := ValidateConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateConfigUnknownMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unknown.json")
	writeFile(t, path, `{"mode":"unknown"}`)

	_, err := ValidateConfig(path)
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestValidateConfigMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.json")
	writeFile(t, path, `{"mode":"client"}`)

	_, err := ValidateConfig(path)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
}

func TestBuildLoggerDefaultInfo(t *testing.T) {
	logger := BuildLogger("info", "")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestBuildLoggerDebug(t *testing.T) {
	logger := BuildLogger("debug", "")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestBuildLoggerWarn(t *testing.T) {
	logger := BuildLogger("warn", "")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestBuildLoggerError(t *testing.T) {
	logger := BuildLogger("error", "")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestBuildLoggerInvalidLevelDefaultsToInfo(t *testing.T) {
	logger := BuildLogger("invalid-level", "")
	if logger == nil {
		t.Fatal("expected non-nil logger for invalid level")
	}
}

func TestBuildLoggerWithFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")
	logger := BuildLogger("info", logPath)
	if logger == nil {
		t.Fatal("expected non-nil logger with file")
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("log file was not created: %v", err)
	}
}

func TestClientConfigTemplateContainsRequiredFields(t *testing.T) {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(ClientConfigTemplate), &parsed); err != nil {
		t.Fatalf("client template is not valid JSON: %v", err)
	}

	required := []string{"mode", "client", "tgp", "ipc", "observability"}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("client template missing required key: %s", key)
		}
	}
}

func TestServerConfigTemplateContainsRequiredFields(t *testing.T) {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(ServerConfigTemplate), &parsed); err != nil {
		t.Fatalf("server template is not valid JSON: %v", err)
	}

	required := []string{"mode", "server", "tgp", "observability"}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("server template missing required key: %s", key)
		}
	}
}

func TestUsageContainsCommandNames(t *testing.T) {
	usage := Usage()
	commands := []string{"run", "validate", "generate-config", "version"}
	for _, cmd := range commands {
		if !contains(usage, cmd) {
			t.Errorf("usage missing command: %s", cmd)
		}
	}
}

func TestCtlUsageContainsCommandNames(t *testing.T) {
	usage := CtlUsage()
	if !contains(usage, "health") {
		t.Error("ctl usage missing health command")
	}
	if !contains(usage, "version") {
		t.Error("ctl usage missing version command")
	}
}

func TestGenerateConfigProducesParseableConfig(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeClient, config.ModeServer} {
		t.Run(string(mode), func(t *testing.T) {
			output, err := GenerateConfig(mode)
			if err != nil {
				t.Fatalf("GenerateConfig(%q): %v", mode, err)
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(output), &parsed); err != nil {
				t.Fatalf("output not valid JSON: %v", err)
			}
			if got, ok := parsed["mode"].(string); !ok || config.Mode(got) != mode {
				t.Errorf("expected mode %q, got %v", mode, parsed["mode"])
			}
		})
	}
}

func TestFlagValueReturnsLongFlag(t *testing.T) {
	value := FlagValue([]string{"--config", "client.json"}, "--config", "-c", "config.json")
	if value != "client.json" {
		t.Fatalf("expected client.json, got %q", value)
	}
}

func TestFlagValueReturnsShortFlag(t *testing.T) {
	value := FlagValue([]string{"-c", "custom.json"}, "--config", "-c", "config.json")
	if value != "custom.json" {
		t.Fatalf("expected custom.json, got %q", value)
	}
}

func TestFlagValueReturnsFallbackWhenAbsent(t *testing.T) {
	value := FlagValue([]string{"other", "args"}, "--config", "-c", "fallback.json")
	if value != "fallback.json" {
		t.Fatalf("expected fallback.json, got %q", value)
	}
}

func TestFlagValueReturnsFallbackWhenFlagMissingValue(t *testing.T) {
	value := FlagValue([]string{"--config"}, "--config", "-c", "default.json")
	if value != "default.json" {
		t.Fatalf("expected default.json when flag has no value, got %q", value)
	}
}

func TestFlagValueReturnsFallbackForEmptyArgs(t *testing.T) {
	value := FlagValue(nil, "--config", "-c", "default.json")
	if value != "default.json" {
		t.Fatalf("expected default.json for nil args, got %q", value)
	}
	value = FlagValue([]string{}, "--config", "-c", "default.json")
	if value != "default.json" {
		t.Fatalf("expected default.json for empty args, got %q", value)
	}
}

func TestFlagValuePicksFirstMatch(t *testing.T) {
	value := FlagValue([]string{"--config", "first.json", "-c", "second.json"}, "--config", "-c", "fallback.json")
	if value != "first.json" {
		t.Fatalf("expected first.json, got %q", value)
	}
}

func TestHasHelpDetectsShortFlag(t *testing.T) {
	if !HasHelp([]string{"-h"}) {
		t.Error("expected -h to be detected")
	}
}

func TestHasHelpDetectsLongFlag(t *testing.T) {
	if !HasHelp([]string{"--help"}) {
		t.Error("expected --help to be detected")
	}
}

func TestHasHelpDetectsFlagAmongOtherArgs(t *testing.T) {
	if !HasHelp([]string{"--config", "client.json", "-h"}) {
		t.Error("expected -h among other args to be detected")
	}
}

func TestHasHelpReturnsFalseWhenAbsent(t *testing.T) {
	if HasHelp([]string{"--config", "client.json"}) {
		t.Error("expected false when no help flag")
	}
}

func TestHasHelpReturnsFalseForEmptyArgs(t *testing.T) {
	if HasHelp(nil) {
		t.Error("expected false for nil args")
	}
	if HasHelp([]string{}) {
		t.Error("expected false for empty args")
	}
}

func TestHasHelpIsCaseSensitive(t *testing.T) {
	if HasHelp([]string{"-H"}) {
		t.Error("expected -H (uppercase) to not match")
	}
	if HasHelp([]string{"--HELP"}) {
		t.Error("expected --HELP to not match")
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
