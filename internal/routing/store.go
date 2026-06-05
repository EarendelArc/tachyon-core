package routing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

var (
	ErrProfileNotFound = errors.New("game profile not found")
	ErrDuplicateID     = errors.New("game profile id already exists")
	ErrInvalidProfile  = errors.New("invalid game profile")
)

type Config struct {
	GameProfiles []GameProfile  `json:"gameProfiles"`
	Launchers    LauncherPolicy `json:"launchers"`
}

func DefaultConfig() Config {
	return Config{
		GameProfiles: nil,
		Launchers: LauncherPolicy{
			Steam: SteamPolicy{
				Enabled:                  true,
				TrackChildProcesses:      true,
				AccelerateGameUDP:        true,
				AccelerateSteamDownloads: false,
			},
		},
	}
}

func (c Config) Engine() Engine {
	return Engine{
		Profiles:  append([]GameProfile(nil), c.GameProfiles...),
		Launchers: c.Launchers,
	}
}

type Store interface {
	Load(ctx context.Context) (Config, error)
	Save(ctx context.Context, cfg Config) error
}

type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) Load(ctx context.Context) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return Config{}, err
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return Config{}, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (s *FileStore) Save(ctx context.Context, cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tachyon-config-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		if renameErr := os.Rename(tmpPath, s.path); renameErr != nil {
			return renameErr
		}
	}
	return nil
}

type MemoryStore struct {
	mu  sync.Mutex
	cfg Config
}

func NewMemoryStore(cfg Config) *MemoryStore {
	return &MemoryStore{cfg: cfg}
}

func (s *MemoryStore) Load(ctx context.Context) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return Config{}, err
	}
	return cloneConfig(s.cfg), nil
}

func (s *MemoryStore) Save(ctx context.Context, cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	s.cfg = cloneConfig(cfg)
	return nil
}

func validateConfig(cfg Config) error {
	ids := make(map[string]struct{}, len(cfg.GameProfiles))
	for _, profile := range cfg.GameProfiles {
		if err := ValidateProfile(profile); err != nil {
			return err
		}
		key := strings.ToLower(profile.ID)
		if _, ok := ids[key]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicateID, profile.ID)
		}
		ids[key] = struct{}{}
	}
	return nil
}

func ValidateProfile(profile GameProfile) error {
	if strings.TrimSpace(profile.ID) == "" {
		return fmt.Errorf("%w: id is required", ErrInvalidProfile)
	}
	if strings.TrimSpace(profile.DisplayName) == "" {
		return fmt.Errorf("%w: displayName is required", ErrInvalidProfile)
	}
	if profile.UDPPolicy == "" {
		profile.UDPPolicy = UDPPolicyTGP
	}
	if profile.TCPPolicy == "" {
		profile.TCPPolicy = TCPPolicyAuto
	}
	if !validUDPPolicy(profile.UDPPolicy) {
		return fmt.Errorf("%w: unsupported udpPolicy %q", ErrInvalidProfile, profile.UDPPolicy)
	}
	if !validTCPPolicy(profile.TCPPolicy) {
		return fmt.Errorf("%w: unsupported tcpPolicy %q", ErrInvalidProfile, profile.TCPPolicy)
	}
	if len(profile.Match.ProcessNames) == 0 &&
		len(profile.Match.Paths) == 0 &&
		len(profile.Match.PathPrefixes) == 0 &&
		len(profile.Match.SHA256) == 0 &&
		len(profile.Match.SteamAppIDs) == 0 {
		return fmt.Errorf("%w: at least one match rule is required", ErrInvalidProfile)
	}
	return nil
}

func validUDPPolicy(policy UDPPolicy) bool {
	return slices.Contains([]UDPPolicy{UDPPolicyAuto, UDPPolicyTGP, UDPPolicyDirect, UDPPolicyBlock}, policy)
}

func validTCPPolicy(policy TCPPolicy) bool {
	return slices.Contains([]TCPPolicy{TCPPolicyAuto, TCPPolicyDirect, TCPPolicyBlock}, policy)
}

func cloneConfig(cfg Config) Config {
	cfg.GameProfiles = append([]GameProfile(nil), cfg.GameProfiles...)
	return cfg
}
