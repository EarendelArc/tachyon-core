package app

import (
	"reflect"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/config"
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
