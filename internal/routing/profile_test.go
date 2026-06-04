package routing

import (
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
)

func TestManualProfileWinsForGameUDP(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "cs2",
				DisplayName: "Counter-Strike 2",
				Enabled:     true,
				Manual:      true,
				Priority:    100,
				Match: MatchRule{
					ProcessNames: []string{"cs2.exe"},
					SteamAppIDs:  []uint32{730},
				},
				UDPPolicy: UDPPolicyTGP,
				TCPPolicy: TCPPolicyAuto,
			},
		},
	}

	decision := engine.Decide(pidtrack.ProcessInfo{Name: "cs2.exe"}, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.Kind != DecisionGame {
		t.Fatalf("expected game decision, got %s", decision.Kind)
	}
	if decision.UDPPolicy != UDPPolicyTGP {
		t.Fatalf("expected tgp udp policy, got %s", decision.UDPPolicy)
	}
	if decision.ProfileID != "cs2" {
		t.Fatalf("expected cs2 profile, got %q", decision.ProfileID)
	}
}

func TestSteamGameProcessAcceleratesUDP(t *testing.T) {
	engine := Engine{
		Launchers: LauncherPolicy{
			Steam: SteamPolicy{
				Enabled:             true,
				TrackChildProcesses: true,
				AccelerateGameUDP:   true,
			},
		},
	}

	proc := pidtrack.ProcessInfo{
		Name:           "eldenring.exe",
		ExecutablePath: `C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game\eldenring.exe`,
		Ancestors: []pidtrack.ProcessSummary{
			{Name: "steam.exe"},
		},
	}

	decision := engine.Decide(proc, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.Kind != DecisionGame {
		t.Fatalf("expected steam game decision, got %s", decision.Kind)
	}
	if decision.UDPPolicy != UDPPolicyTGP {
		t.Fatalf("expected tgp udp policy, got %s", decision.UDPPolicy)
	}
}

func TestSteamClientItselfDoesNotBecomeGame(t *testing.T) {
	engine := Engine{
		Launchers: LauncherPolicy{
			Steam: SteamPolicy{
				Enabled:             true,
				TrackChildProcesses: true,
				AccelerateGameUDP:   true,
			},
		},
	}

	decision := engine.Decide(pidtrack.ProcessInfo{Name: "steamwebhelper.exe"}, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.Kind == DecisionGame {
		t.Fatal("steam helper should not be accelerated as a game process")
	}
}
