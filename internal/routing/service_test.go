package routing

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestServiceAddListUpdateRemoveGameProfile(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMemoryStore(DefaultConfig()))

	profile, err := service.AddGameProfile(ctx, GameProfile{
		ID:          "manual-game",
		DisplayName: "Manual Game",
		Enabled:     true,
		Manual:      true,
		Priority:    50,
		Match: MatchRule{
			ProcessNames: []string{"manual.exe"},
		},
	})
	if err != nil {
		t.Fatalf("add profile: %v", err)
	}
	if profile.UDPPolicy != UDPPolicyTGP {
		t.Fatalf("expected default udp policy tgp, got %s", profile.UDPPolicy)
	}
	if profile.TCPPolicy != TCPPolicyAuto {
		t.Fatalf("expected default tcp policy auto, got %s", profile.TCPPolicy)
	}

	profiles, err := service.ListGameProfiles(ctx)
	if err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one profile, got %d", len(profiles))
	}

	updated := profiles[0]
	updated.DisplayName = "Manual Game Updated"
	updated.Match.ProcessNames = []string{"updated.exe"}
	if _, err := service.UpdateGameProfile(ctx, "manual-game", updated); err != nil {
		t.Fatalf("update profile: %v", err)
	}

	if err := service.RemoveGameProfile(ctx, "manual-game"); err != nil {
		t.Fatalf("remove profile: %v", err)
	}
	profiles, err = service.ListGameProfiles(ctx)
	if err != nil {
		t.Fatalf("list after remove: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected no profiles after remove, got %d", len(profiles))
	}
}

func TestServiceRejectsDuplicateProfileID(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMemoryStore(DefaultConfig()))
	profile := GameProfile{
		ID:          "dup",
		DisplayName: "Duplicate",
		Enabled:     true,
		Manual:      true,
		Match:       MatchRule{ProcessNames: []string{"dup.exe"}},
	}

	if _, err := service.AddGameProfile(ctx, profile); err != nil {
		t.Fatalf("first add failed: %v", err)
	}
	if _, err := service.AddGameProfile(ctx, profile); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestFileStorePersistsConfig(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tachyon-core.json")
	store := NewFileStore(path)
	service := NewService(store)

	if _, err := service.AddGameProfile(ctx, GameProfile{
		ID:          "persisted",
		DisplayName: "Persisted Game",
		Enabled:     true,
		Manual:      true,
		Match:       MatchRule{Paths: []string{`C:\Games\game.exe`}},
	}); err != nil {
		t.Fatalf("add persisted profile: %v", err)
	}

	reloaded := NewService(NewFileStore(path))
	profiles, err := reloaded.ListGameProfiles(ctx)
	if err != nil {
		t.Fatalf("reload profiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].ID != "persisted" {
		t.Fatalf("unexpected reloaded profiles: %#v", profiles)
	}
}
