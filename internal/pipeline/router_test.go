package pipeline

import (
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/routing"
)

func TestRouterConfigRuleWinsByPriority(t *testing.T) {
	router := NewRouter(config.RoutingConfig{
		DefaultAction: "direct",
		Rules: []config.RouteRule{
			{CIDR: "8.8.8.0/24", Action: "direct", Priority: 10},
			{Protocol: "udp", Action: "tgp", Priority: 100},
		},
	}, routing.Engine{})

	decision := router.Decide(pidtrack.FlowKey{
		Transport: pidtrack.TransportUDP,
		RemoteIP:  "8.8.8.8",
	}, pidtrack.ProcessInfo{})
	if decision.Action != ActionTGP {
		t.Fatalf("expected priority udp rule to win, got %s", decision.Action)
	}
}

func TestRouterGameProfileRoutesUDPToTGP(t *testing.T) {
	router := NewRouter(config.RoutingConfig{DefaultAction: "direct"}, routing.Engine{
		Profiles: []routing.GameProfile{
			{
				ID:          "game",
				DisplayName: "Game",
				Enabled:     true,
				Manual:      true,
				Match:       routing.MatchRule{ProcessNames: []string{"game.exe"}},
				UDPPolicy:   routing.UDPPolicyTGP,
			},
		},
	})

	decision := router.Decide(pidtrack.FlowKey{
		Transport: pidtrack.TransportUDP,
		RemoteIP:  "203.0.113.1",
	}, pidtrack.ProcessInfo{Name: "game.exe"})
	if decision.Action != ActionTGP {
		t.Fatalf("expected tgp, got %s", decision.Action)
	}
}

func TestRouterManualGameProfileWinsOverConfigRules(t *testing.T) {
	router := NewRouter(config.RoutingConfig{
		DefaultAction: "direct",
		Rules: []config.RouteRule{
			{ProcessName: "game.exe", Action: "direct", Priority: 1000},
		},
	}, routing.Engine{
		Profiles: []routing.GameProfile{
			{
				ID:          "manual-game",
				DisplayName: "Manual Game",
				Enabled:     true,
				Manual:      true,
				Match:       routing.MatchRule{ProcessNames: []string{"game.exe"}},
				UDPPolicy:   routing.UDPPolicyTGP,
			},
		},
	})

	decision := router.Decide(pidtrack.FlowKey{
		Transport: pidtrack.TransportUDP,
		RemoteIP:  "203.0.113.1",
	}, pidtrack.ProcessInfo{Name: "game.exe"})
	if decision.Action != ActionTGP {
		t.Fatalf("expected manual game profile to win, got %s", decision.Action)
	}
}
