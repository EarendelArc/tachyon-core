package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

const (
	defaultPublicE2ETimeout = 8 * time.Second
	maxPublicE2ETimeout     = 30 * time.Second
	maxPublicE2EPayload     = 1200
)

type publicE2EConfig struct {
	server       string
	target       string
	psk          string
	timeout      time.Duration
	payload      []byte
	expect       []byte
	expectPrefix []byte
}

func TestTGPRelayPublicE2EFromEnv(t *testing.T) {
	cfg, enabled, err := publicE2EConfigFromEnv(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("set TACHYON_E2E_SERVER, TACHYON_E2E_TARGET, and TACHYON_E2E_PSK to run public TGP E2E")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	server, err := resolvePublicE2EAddr(ctx, cfg.server)
	if err != nil {
		t.Fatalf("resolve TACHYON_E2E_SERVER: %v", err)
	}
	target, err := resolvePublicE2EAddr(ctx, cfg.target)
	if err != nil {
		t.Fatalf("resolve TACHYON_E2E_TARGET: %v", err)
	}

	gotCh := make(chan tgp.TunnelDatagram, 1)
	manager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr: server.String(),
		LocalAddrs: []string{
			"0.0.0.0:0",
		},
		PacerPPS: 1000,
		FEC: tgpFECOptions(config.FECConfig{
			DataShards:   2,
			ParityShards: 1,
			GroupTimeout: 20 * time.Millisecond,
			Dynamic:      true,
			AdaptWindow:  8,
		}),
		DisableMigration: false,
		AuthKey:          []byte(cfg.psk),
		HandshakeTimeout: cfg.timeout,
		OnDatagram: func(_ context.Context, datagram tgp.TunnelDatagram) error {
			select {
			case gotCh <- datagram:
			default:
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("create TGP E2E client manager: %v", err)
	}
	defer manager.Close()

	sendSmokeTunnelDatagram(t, ctx, manager, target, cfg.payload)
	select {
	case got := <-gotCh:
		assertPublicE2EResponse(t, got, target, cfg)
	case <-ctx.Done():
		t.Fatalf("timeout waiting for TGP E2E response from %s via %s: %v", cfg.target, cfg.server, ctx.Err())
	}
}

func TestPublicE2EConfigFromEnv(t *testing.T) {
	valid := map[string]string{
		"TACHYON_E2E_SERVER": "vps.example.com:443",
		"TACHYON_E2E_TARGET": "echo.example.com:27015",
		"TACHYON_E2E_PSK":    "0123456789abcdef",
	}
	tests := []struct {
		name        string
		overrides   map[string]string
		wantEnabled bool
		wantErr     string
	}{
		{name: "disabled without required variables"},
		{
			name: "optional variables alone remain disabled",
			overrides: map[string]string{
				"TACHYON_E2E_TIMEOUT": "1s",
				"TACHYON_E2E_PAYLOAD": "offline",
			},
		},
		{
			name:      "rejects partial opt in",
			overrides: map[string]string{"TACHYON_E2E_SERVER": valid["TACHYON_E2E_SERVER"]},
			wantErr:   "requires TACHYON_E2E_SERVER, TACHYON_E2E_TARGET, and TACHYON_E2E_PSK",
		},
		{
			name:        "accepts complete opt in",
			overrides:   valid,
			wantEnabled: true,
		},
		{
			name: "rejects short psk",
			overrides: mergeE2EEnv(valid, map[string]string{
				"TACHYON_E2E_PSK": "too-short",
			}),
			wantErr: "must be at least 16 characters",
		},
		{
			name: "rejects invalid timeout",
			overrides: mergeE2EEnv(valid, map[string]string{
				"TACHYON_E2E_TIMEOUT": "soon",
			}),
			wantErr: "parse TACHYON_E2E_TIMEOUT",
		},
		{
			name: "rejects zero timeout",
			overrides: mergeE2EEnv(valid, map[string]string{
				"TACHYON_E2E_TIMEOUT": "0s",
			}),
			wantErr: "must be >0 and <=30s",
		},
		{
			name: "rejects excessive timeout",
			overrides: mergeE2EEnv(valid, map[string]string{
				"TACHYON_E2E_TIMEOUT": "31s",
			}),
			wantErr: "must be >0 and <=30s",
		},
		{
			name: "rejects oversized payload",
			overrides: mergeE2EEnv(valid, map[string]string{
				"TACHYON_E2E_PAYLOAD": strings.Repeat("x", maxPublicE2EPayload+1),
			}),
			wantErr: "must be <=1200 bytes",
		},
		{
			name: "rejects ambiguous expectations",
			overrides: mergeE2EEnv(valid, map[string]string{
				"TACHYON_E2E_EXPECT":        "reply",
				"TACHYON_E2E_EXPECT_PREFIX": "rep",
			}),
			wantErr: "set only one of TACHYON_E2E_EXPECT and TACHYON_E2E_EXPECT_PREFIX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, enabled, err := publicE2EConfigFromEnv(func(key string) string {
				return tt.overrides[key]
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if enabled != tt.wantEnabled {
				t.Fatalf("enabled = %t, want %t", enabled, tt.wantEnabled)
			}
			if enabled {
				if cfg.timeout != defaultPublicE2ETimeout {
					t.Fatalf("timeout = %s, want %s", cfg.timeout, defaultPublicE2ETimeout)
				}
				if string(cfg.payload) != "tachyon-e2e-probe" {
					t.Fatalf("payload = %q, want default", cfg.payload)
				}
			}
		})
	}
}

func TestResolvePublicE2EAddrLiteral(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	tests := []struct {
		raw     string
		want    string
		wantErr string
	}{
		{raw: "192.0.2.10:443", want: "192.0.2.10:443"},
		{raw: "[2001:db8::10]:27015", want: "[2001:db8::10]:27015"},
		{raw: "192.0.2.10", wantErr: "missing port"},
		{raw: "192.0.2.10:0", wantErr: "invalid UDP port"},
		{raw: "192.0.2.10:65536", wantErr: "invalid UDP port"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := resolvePublicE2EAddr(ctx, tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("address = %s, want %s", got, tt.want)
			}
		})
	}
}

func publicE2EConfigFromEnv(getenv func(string) string) (publicE2EConfig, bool, error) {
	server := strings.TrimSpace(getenv("TACHYON_E2E_SERVER"))
	target := strings.TrimSpace(getenv("TACHYON_E2E_TARGET"))
	psk := strings.TrimSpace(getenv("TACHYON_E2E_PSK"))
	if server == "" && target == "" && psk == "" {
		return publicE2EConfig{}, false, nil
	}
	if server == "" || target == "" || psk == "" {
		return publicE2EConfig{}, false, fmt.Errorf("public TGP E2E requires TACHYON_E2E_SERVER, TACHYON_E2E_TARGET, and TACHYON_E2E_PSK")
	}
	if len(psk) < 16 {
		return publicE2EConfig{}, false, fmt.Errorf("TACHYON_E2E_PSK must be at least 16 characters")
	}

	timeout := defaultPublicE2ETimeout
	if raw := strings.TrimSpace(getenv("TACHYON_E2E_TIMEOUT")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return publicE2EConfig{}, false, fmt.Errorf("parse TACHYON_E2E_TIMEOUT: %w", err)
		}
		timeout = parsed
	}
	if timeout <= 0 || timeout > maxPublicE2ETimeout {
		return publicE2EConfig{}, false, fmt.Errorf("TACHYON_E2E_TIMEOUT must be >0 and <=30s, got %s", timeout)
	}

	payload := []byte(strings.TrimSpace(getenv("TACHYON_E2E_PAYLOAD")))
	if len(payload) == 0 {
		payload = []byte("tachyon-e2e-probe")
	}
	if len(payload) > maxPublicE2EPayload {
		return publicE2EConfig{}, false, fmt.Errorf("TACHYON_E2E_PAYLOAD must be <=1200 bytes")
	}
	expect := []byte(strings.TrimSpace(getenv("TACHYON_E2E_EXPECT")))
	expectPrefix := []byte(strings.TrimSpace(getenv("TACHYON_E2E_EXPECT_PREFIX")))
	if len(expect) > 0 && len(expectPrefix) > 0 {
		return publicE2EConfig{}, false, fmt.Errorf("set only one of TACHYON_E2E_EXPECT and TACHYON_E2E_EXPECT_PREFIX")
	}

	return publicE2EConfig{
		server:       server,
		target:       target,
		psk:          psk,
		timeout:      timeout,
		payload:      payload,
		expect:       expect,
		expectPrefix: expectPrefix,
	}, true, nil
}

func resolvePublicE2EAddr(ctx context.Context, raw string) (netip.AddrPort, error) {
	host, portRaw, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid UDP port %q", portRaw)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, addr := range addrs {
		if addr.IsValid() {
			return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("missing resolved IP for %q", raw)
}

func assertPublicE2EResponse(t *testing.T, got tgp.TunnelDatagram, target netip.AddrPort, cfg publicE2EConfig) {
	t.Helper()
	if got.RemoteAddrPort() != target {
		t.Fatalf("response remote address = %s, want %s", got.RemoteAddrPort(), target)
	}
	if len(cfg.expect) > 0 {
		if !bytes.Equal(got.Payload, cfg.expect) {
			t.Fatalf("unexpected E2E response payload %q, want %q", got.Payload, cfg.expect)
		}
		return
	}
	if len(cfg.expectPrefix) > 0 {
		if !bytes.HasPrefix(got.Payload, cfg.expectPrefix) {
			t.Fatalf("unexpected E2E response payload %q, want prefix %q", got.Payload, cfg.expectPrefix)
		}
		return
	}
	if bytes.Equal(got.Payload, cfg.payload) {
		return
	}
	echoPayload := append([]byte("echo:"), cfg.payload...)
	if bytes.Equal(got.Payload, echoPayload) {
		return
	}
	t.Fatalf("unexpected E2E response payload %q, want %q or %q", got.Payload, cfg.payload, echoPayload)
}

func mergeE2EEnv(base, overrides map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(overrides))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range overrides {
		merged[key] = value
	}
	return merged
}
