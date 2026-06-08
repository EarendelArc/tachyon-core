package routing

import (
	"context"
	"errors"
	"os"
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

func TestValidateProfileRejectsEmptyID(t *testing.T) {
	err := ValidateProfile(GameProfile{
		ID:          "",
		DisplayName: "Test",
		Match:       MatchRule{ProcessNames: []string{"test.exe"}},
	})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("expected ErrInvalidProfile, got %v", err)
	}
}

func TestValidateProfileRejectsEmptyDisplayName(t *testing.T) {
	err := ValidateProfile(GameProfile{
		ID:          "test",
		DisplayName: "  ",
		Match:       MatchRule{ProcessNames: []string{"test.exe"}},
	})
	if err == nil {
		t.Fatal("expected error for empty display name")
	}
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("expected ErrInvalidProfile, got %v", err)
	}
}

func TestValidateProfileRejectsNoMatchRules(t *testing.T) {
	err := ValidateProfile(GameProfile{
		ID:          "test",
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error for no match rules")
	}
}

func TestValidateProfileRejectsInvalidUDPPolicy(t *testing.T) {
	err := ValidateProfile(GameProfile{
		ID:          "test",
		DisplayName: "Test",
		Match:       MatchRule{ProcessNames: []string{"test.exe"}},
		UDPPolicy:   "bad",
	})
	if err == nil {
		t.Fatal("expected error for invalid UDP policy")
	}
}

func TestValidateProfileRejectsInvalidTCPPolicy(t *testing.T) {
	err := ValidateProfile(GameProfile{
		ID:          "test",
		DisplayName: "Test",
		Match:       MatchRule{ProcessNames: []string{"test.exe"}},
		TCPPolicy:   "bad",
	})
	if err == nil {
		t.Fatal("expected error for invalid TCP policy")
	}
}

func TestValidateProfileAcceptsValidProfile(t *testing.T) {
	err := ValidateProfile(GameProfile{
		ID:          "test",
		DisplayName: "Test",
		Enabled:     true,
		Manual:      true,
		Match:       MatchRule{ProcessNames: []string{"test.exe"}},
		UDPPolicy:   UDPPolicyTGP,
		TCPPolicy:   TCPPolicyAuto,
	})
	if err != nil {
		t.Fatalf("expected valid profile, got error: %v", err)
	}
}

func TestDefaultConfigHasSteamEnabled(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Launchers.Steam.Enabled {
		t.Fatal("expected steam enabled by default")
	}
	if !cfg.Launchers.Steam.TrackChildProcesses {
		t.Fatal("expected trackChildProcesses enabled by default")
	}
	if !cfg.Launchers.Steam.AccelerateGameUDP {
		t.Fatal("expected accelerateGameUdp enabled by default")
	}
	if cfg.Launchers.Steam.AccelerateSteamDownloads {
		t.Fatal("expected accelerateSteamDownloads disabled by default")
	}
	if len(cfg.GameProfiles) != 0 {
		t.Fatalf("expected no default game profiles, got %d", len(cfg.GameProfiles))
	}
}

func TestConfigEngineReturnsCopyOfProfiles(t *testing.T) {
	cfg := Config{
		GameProfiles: []GameProfile{
			{ID: "a", DisplayName: "A", Match: MatchRule{ProcessNames: []string{"a.exe"}}},
		},
	}
	engine := cfg.Engine()
	engine.Profiles[0].ID = "mutated"

	if cfg.GameProfiles[0].ID == "mutated" {
		t.Fatal("engine profiles should not alias config profiles")
	}
}

func TestFileStoreLoadReturnsDefaultForMissingFile(t *testing.T) {
	ctx := context.Background()
	store := NewFileStore(filepath.Join(t.TempDir(), "nonexistent.json"))
	cfg, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if cfg.Launchers.Steam.Enabled != true {
		t.Fatal("expected default config for missing file")
	}
}

func TestFileStoreLoadReturnsErrorForInvalidJSON(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := NewFileStore(path)
	_, err := store.Load(ctx)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFileStoreLoadReturnsErrorForCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewFileStore(filepath.Join(t.TempDir(), "any.json"))
	_, err := store.Load(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestMemoryStoreLoadReturnsErrorForCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewMemoryStore(DefaultConfig())
	_, err := store.Load(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestMemoryStoreSaveReturnsErrorForCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewMemoryStore(DefaultConfig())
	err := store.Save(ctx, DefaultConfig())
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
