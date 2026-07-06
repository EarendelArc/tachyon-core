// Package cli provides core CLI command implementations that can be
// tested independently of the cmd/... entry points.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/config"
)

// GenerateConfig returns a JSON config template for the given mode.
func GenerateConfig(mode config.Mode) (string, error) {
	switch mode {
	case config.ModeClient:
		return ClientConfigTemplate, nil
	case config.ModeServer:
		return ServerConfigTemplate, nil
	default:
		return "", fmt.Errorf("unknown mode %q; use 'client' or 'server'", mode)
	}
}

// ValidateConfig loads a config file and returns the mode on success.
func ValidateConfig(path string) (config.Mode, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return "", fmt.Errorf("invalid config %q: %w", path, err)
	}
	return cfg.Mode, nil
}

// BuildLogger creates a structured logger with the given settings.
func BuildLogger(level, logFile string) *slog.Logger {
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
			_ = f.Close()
			return slog.New(slog.NewJSONHandler(appendFileWriter{path: logFile}, opts))
		}
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

type appendFileWriter struct {
	path string
}

func (w appendFileWriter) Write(p []byte) (int, error) {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Write(p)
}

// HealthResponse is the parsed health endpoint response.
type HealthResponse struct {
	StatusCode int
	Body       map[string]any
}

// HealthCheck queries the Core health endpoint and returns the response.
func HealthCheck(addr string) (*HealthResponse, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/v1/health")
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return &HealthResponse{
			StatusCode: resp.StatusCode,
			Body:       map[string]any{"raw": string(body)},
		}, nil
	}
	return &HealthResponse{
		StatusCode: resp.StatusCode,
		Body:       parsed,
	}, nil
}

// Usage returns the tachyon-core usage string.
func Usage() string {
	return "tachyon-core - Tachyon network daemon\n\n" +
		"USAGE:\n" +
		"  tachyon-core <command> [options]\n\n" +
		"COMMANDS:\n" +
		"  run               Start the daemon (client or server mode)\n" +
		"    --config/-c     Path to config file (default: config.json)\n\n" +
		"  validate          Validate a config file (does not start daemon)\n" +
		"    --config/-c     Path to config file (default: config.json)\n\n" +
		"  doctor            Print read-only startup preflight diagnostics as JSON\n" +
		"  preflight         Alias for doctor\n" +
		"    --config/-c     Path to config file (default: config.json)\n" +
		"    --json          Emit structured JSON for Prism/Core orchestration\n\n" +
		"  generate-config   Print a JSON config template to stdout\n" +
		"    --mode/-m       \"client\" or \"server\" (default: client)\n\n" +
		"  version           Print version information\n\n" +
		"EXAMPLES:\n" +
		"  # Start as a client daemon\n" +
		"  tachyon-core run --config /etc/tachyon/client.json\n\n" +
		"  # Validate a config file\n" +
		"  tachyon-core validate --config client.json\n\n" +
		"  # Explain TUN/Wintun/permission readiness without starting Core\n" +
		"  tachyon-core doctor --config client.json --json\n" +
		"  tachyon-core preflight --config client.json --json\n\n" +
		"  # Generate a client config template\n" +
		"  tachyon-core generate-config --mode client > client.json\n"
}

// FlagValue returns the value of a CLI flag from args, or fallback when absent.
// Both long (--flag) and short (-f) forms are recognised.
func FlagValue(args []string, long, short, fallback string) string {
	for i, a := range args {
		if (a == long || a == short) && i+1 < len(args) {
			return args[i+1]
		}
	}
	return fallback
}

// HasHelp returns true when the argument list contains -h or --help.
func HasHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// CtlUsage returns the tachyonctl usage string.
func CtlUsage() string {
	return "tachyonctl - Tachyon Core control CLI\n\n" +
		"USAGE:\n" +
		"  tachyonctl <command> [options]\n\n" +
		"COMMANDS:\n" +
		"  health           Query the Core health endpoint\n" +
		"    --addr/-a      Core HTTP address (default: 127.0.0.1:55123)\n\n" +
		"  version          Print version information\n"
}
