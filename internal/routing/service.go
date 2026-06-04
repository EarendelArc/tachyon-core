package routing

import (
	"context"
	"errors"
	"strings"
	"sync"
)

type Service struct {
	store Store
	mu    sync.Mutex
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Config(ctx context.Context) (Config, error) {
	return s.store.Load(ctx)
}

func (s *Service) Engine(ctx context.Context) (Engine, error) {
	cfg, err := s.Config(ctx)
	if err != nil {
		return Engine{}, err
	}
	return cfg.Engine(), nil
}

func (s *Service) ListGameProfiles(ctx context.Context) ([]GameProfile, error) {
	cfg, err := s.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	return append([]GameProfile(nil), cfg.GameProfiles...), nil
}

func (s *Service) AddGameProfile(ctx context.Context, profile GameProfile) (GameProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	profile = normalizeProfile(profile)
	if err := ValidateProfile(profile); err != nil {
		return GameProfile{}, err
	}

	cfg, err := s.store.Load(ctx)
	if err != nil {
		return GameProfile{}, err
	}
	if findProfileIndex(cfg.GameProfiles, profile.ID) >= 0 {
		return GameProfile{}, ErrDuplicateID
	}

	cfg.GameProfiles = append(cfg.GameProfiles, profile)
	if err := s.store.Save(ctx, cfg); err != nil {
		return GameProfile{}, err
	}
	return profile, nil
}

func (s *Service) UpdateGameProfile(ctx context.Context, id string, profile GameProfile) (GameProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(id) == "" {
		return GameProfile{}, ErrProfileNotFound
	}
	profile.ID = id
	profile = normalizeProfile(profile)
	if err := ValidateProfile(profile); err != nil {
		return GameProfile{}, err
	}

	cfg, err := s.store.Load(ctx)
	if err != nil {
		return GameProfile{}, err
	}
	idx := findProfileIndex(cfg.GameProfiles, id)
	if idx < 0 {
		return GameProfile{}, ErrProfileNotFound
	}

	cfg.GameProfiles[idx] = profile
	if err := s.store.Save(ctx, cfg); err != nil {
		return GameProfile{}, err
	}
	return profile, nil
}

func (s *Service) RemoveGameProfile(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.store.Load(ctx)
	if err != nil {
		return err
	}
	idx := findProfileIndex(cfg.GameProfiles, id)
	if idx < 0 {
		return ErrProfileNotFound
	}

	cfg.GameProfiles = append(cfg.GameProfiles[:idx], cfg.GameProfiles[idx+1:]...)
	return s.store.Save(ctx, cfg)
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrProfileNotFound)
}

func findProfileIndex(profiles []GameProfile, id string) int {
	for idx, profile := range profiles {
		if strings.EqualFold(profile.ID, id) {
			return idx
		}
	}
	return -1
}

func normalizeProfile(profile GameProfile) GameProfile {
	profile.ID = strings.TrimSpace(profile.ID)
	profile.DisplayName = strings.TrimSpace(profile.DisplayName)
	if profile.UDPPolicy == "" {
		profile.UDPPolicy = UDPPolicyTGP
	}
	if profile.TCPPolicy == "" {
		profile.TCPPolicy = TCPPolicyAuto
	}
	profile.Match.ProcessNames = trimStrings(profile.Match.ProcessNames)
	profile.Match.Paths = trimStrings(profile.Match.Paths)
	profile.Match.PathPrefixes = trimStrings(profile.Match.PathPrefixes)
	profile.Match.SHA256 = trimStrings(profile.Match.SHA256)
	return profile
}

func trimStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
