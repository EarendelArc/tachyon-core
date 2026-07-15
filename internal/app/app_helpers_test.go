package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/tun"
)

func TestClientTGPLocalAddrsHonorsMultipathFlag(t *testing.T) {
	cfg := config.ProxyConfig{
		LocalAddrs: []string{
			" 127.0.0.1:0 ",
			"",
			"127.0.0.2:0",
		},
	}

	if got, want := clientTGPLocalAddrs(cfg, false), []string{"127.0.0.1:0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("single-path local addrs = %#v, want %#v", got, want)
	}
	if got, want := clientTGPLocalAddrs(cfg, true), []string{"127.0.0.1:0", "127.0.0.2:0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("multipath local addrs = %#v, want %#v", got, want)
	}
}

func TestParseGameRoutePrefixesNormalizesHostBits(t *testing.T) {
	got, err := parseGameRoutePrefixes([]string{" 203.0.113.42/24 ", "2001:db8:1::5/64"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:1::/64"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
}

func TestResolveTGPRelayAddressesAcceptsIPLiteralWithoutDNS(t *testing.T) {
	for _, raw := range []string{"198.51.100.8:443", "[2001:db8::8]:443"} {
		got, err := resolveTGPRelayAddresses(context.Background(), raw)
		if err != nil {
			t.Fatalf("resolve %s: %v", raw, err)
		}
		if len(got) != 1 {
			t.Fatalf("resolve %s = %v", raw, got)
		}
	}
}

func TestRelayExclusionsSkipResolutionWithoutGameRoutes(t *testing.T) {
	called := false
	got, err := relayExclusionsForGameRoutes(
		context.Background(),
		nil,
		"unresolvable.invalid:443",
		func(context.Context, string) ([]netip.Addr, error) {
			called = true
			return nil, errors.New("injected DNS failure")
		},
	)
	if err != nil {
		t.Fatalf("empty game routes must not depend on Relay DNS: %v", err)
	}
	if called {
		t.Fatal("Relay resolver called for empty game routes")
	}
	if len(got) != 0 {
		t.Fatalf("exclusions = %v, want empty", got)
	}
}

func TestRelayExclusionsFailClosedOnResolutionFailureWithGameRoutes(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	injected := errors.New("injected DNS failure")
	_, err := relayExclusionsForGameRoutes(
		context.Background(),
		routes,
		"relay.example.invalid:443",
		func(context.Context, string) ([]netip.Addr, error) {
			return nil, injected
		},
	)
	if !errors.Is(err, injected) {
		t.Fatalf("error = %v, want injected DNS failure", err)
	}
}

func TestValidateTGPRemoteRouteRejectsRelayRecursion(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	err := validateTGPRemoteRoute(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 443}, routes)
	if !errors.Is(err, tun.ErrRelayRouteConflict) {
		t.Fatalf("error = %v, want ErrRelayRouteConflict", err)
	}
	if err := validateTGPRemoteRoute(&net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}, routes); err != nil {
		t.Fatalf("non-overlapping relay rejected: %v", err)
	}
}

func TestTGPPacerPPSHonorsMaxRateCeiling(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.PacingConfig
		want float64
	}{
		{
			name: "no ceiling",
			cfg:  config.PacingConfig{InitialRatePPS: 180, MaxRatePPS: 0},
			want: 180,
		},
		{
			name: "ceiling below initial",
			cfg:  config.PacingConfig{InitialRatePPS: 500, MaxRatePPS: 128},
			want: 128,
		},
		{
			name: "ceiling above initial",
			cfg:  config.PacingConfig{InitialRatePPS: 128, MaxRatePPS: 500},
			want: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tgpPacerPPS(tt.cfg); got != tt.want {
				t.Fatalf("tgpPacerPPS() = %v, want %v", got, tt.want)
			}
		})
	}
}
