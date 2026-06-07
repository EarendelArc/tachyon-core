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


func TestDisabledProfileDoesNotMatch(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "disabled",
				DisplayName: "Disabled Game",
				Enabled:     false,
				Manual:      true,
				Priority:    100,
				Match:       MatchRule{ProcessNames: []string{"disabled.exe"}},
				UDPPolicy:   UDPPolicyTGP,
			},
		},
	}

	decision := engine.Decide(pidtrack.ProcessInfo{Name: "disabled.exe"}, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.Kind == DecisionGame {
		t.Fatal("disabled profile should not match")
	}
	if decision.Kind != DecisionDefault {
		t.Fatalf("expected default decision for disabled profile, got %s", decision.Kind)
	}
}

func TestManualProfileBeatsAutomatic(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "auto",
				DisplayName: "Auto Profile",
				Enabled:     true,
				Manual:      false,
				Priority:    200,
				Match:       MatchRule{ProcessNames: []string{"game.exe"}},
				UDPPolicy:   UDPPolicyDirect,
			},
			{
				ID:          "manual",
				DisplayName: "Manual Profile",
				Enabled:     true,
				Manual:      true,
				Priority:    10,
				Match:       MatchRule{ProcessNames: []string{"game.exe"}},
				UDPPolicy:   UDPPolicyTGP,
			},
		},
	}

	decision := engine.Decide(pidtrack.ProcessInfo{Name: "game.exe"}, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.ProfileID != "manual" {
		t.Fatalf("expected manual profile to win, got %q", decision.ProfileID)
	}
	if decision.UDPPolicy != UDPPolicyTGP {
		t.Fatalf("expected tgp policy from manual, got %s", decision.UDPPolicy)
	}
}

func TestMultipleManualProfilesHigherPriorityWins(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "low",
				DisplayName: "Low Priority",
				Enabled:     true,
				Manual:      true,
				Priority:    10,
				Match:       MatchRule{ProcessNames: []string{"game.exe"}},
				UDPPolicy:   UDPPolicyDirect,
			},
			{
				ID:          "high",
				DisplayName: "High Priority",
				Enabled:     true,
				Manual:      true,
				Priority:    100,
				Match:       MatchRule{ProcessNames: []string{"game.exe"}},
				UDPPolicy:   UDPPolicyTGP,
			},
		},
	}

	decision := engine.Decide(pidtrack.ProcessInfo{Name: "game.exe"}, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.ProfileID != "high" {
		t.Fatalf("expected high priority to win, got %q", decision.ProfileID)
	}
}

func TestPathMatchingWithNormalizedSlashes(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "path-match",
				DisplayName: "Path Match",
				Enabled:     true,
				Manual:      true,
				Priority:    100,
				Match:       MatchRule{Paths: []string{`C:\Games\game.exe`}},
				UDPPolicy:   UDPPolicyTGP,
			},
		},
	}

	decision := engine.Decide(
		pidtrack.ProcessInfo{ExecutablePath: `C:/Games/game.exe`},
		pidtrack.FlowKey{Transport: pidtrack.TransportUDP},
	)
	if decision.ProfileID != "path-match" {
		t.Fatalf("expected path match, got %q decision", decision.Kind)
	}
}

func TestPathPrefixMatching(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "prefix-match",
				DisplayName: "Prefix Match",
				Enabled:     true,
				Manual:      true,
				Priority:    100,
				Match:       MatchRule{PathPrefixes: []string{`C:\Games`}},
				UDPPolicy:   UDPPolicyTGP,
			},
		},
	}

	decision := engine.Decide(
		pidtrack.ProcessInfo{ExecutablePath: `C:\Games\sub\game.exe`},
		pidtrack.FlowKey{Transport: pidtrack.TransportUDP},
	)
	if decision.ProfileID != "prefix-match" {
		t.Fatalf("expected prefix match, got %q decision", decision.Kind)
	}
}

func TestDefaultDecisionWhenNoMatch(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "other",
				DisplayName: "Other Game",
				Enabled:     true,
				Manual:      true,
				Priority:    100,
				Match:       MatchRule{ProcessNames: []string{"other.exe"}},
				UDPPolicy:   UDPPolicyTGP,
			},
		},
	}

	decision := engine.Decide(pidtrack.ProcessInfo{Name: "unknown.exe"}, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.Kind != DecisionDefault {
		t.Fatalf("expected default decision, got %s", decision.Kind)
	}
	if decision.UDPPolicy != UDPPolicyAuto {
		t.Fatalf("expected auto udp policy, got %s", decision.UDPPolicy)
	}
}

func TestEmptyPolicyDefaults(t *testing.T) {
	engine := Engine{
		Profiles: []GameProfile{
			{
				ID:          "defaults",
				DisplayName: "Default Policies",
				Enabled:     true,
				Manual:      true,
				Priority:    100,
				Match:       MatchRule{ProcessNames: []string{"game.exe"}},
				UDPPolicy:   "",
				TCPPolicy:   "",
			},
		},
	}

	decision := engine.Decide(pidtrack.ProcessInfo{Name: "game.exe"}, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.UDPPolicy != UDPPolicyTGP {
		t.Fatalf("expected default tgp udp policy, got %s", decision.UDPPolicy)
	}
	if decision.TCPPolicy != TCPPolicyAuto {
		t.Fatalf("expected default auto tcp policy, got %s", decision.TCPPolicy)
	}
}

func TestSteamDisabledDoesNotAccelerate(t *testing.T) {
	engine := Engine{
		Launchers: LauncherPolicy{
			Steam: SteamPolicy{
				Enabled:             false,
				TrackChildProcesses: true,
				AccelerateGameUDP:   true,
			},
		},
	}

	proc := pidtrack.ProcessInfo{
		Name:           "game.exe",
		ExecutablePath: `C:\Steam\steamapps\common\Game\game.exe`,
	}

	decision := engine.Decide(proc, pidtrack.FlowKey{Transport: pidtrack.TransportUDP})
	if decision.Kind == DecisionGame {
		t.Fatal("steam disabled should not accelerate game process")
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
