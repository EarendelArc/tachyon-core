package routing

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
)

type UDPPolicy string

const (
	UDPPolicyAuto   UDPPolicy = "auto"
	UDPPolicyTGP    UDPPolicy = "tgp"
	UDPPolicyDirect UDPPolicy = "direct"
	UDPPolicyBlock  UDPPolicy = "block"
)

type TCPPolicy string

const (
	TCPPolicyAuto   TCPPolicy = "auto"
	TCPPolicyDirect TCPPolicy = "direct"
	TCPPolicyBlock  TCPPolicy = "block"
)

type DecisionKind string

const (
	DecisionDefault DecisionKind = "default"
	DecisionGame    DecisionKind = "game"
	DecisionProxy   DecisionKind = "proxy"
	DecisionDirect  DecisionKind = "direct"
	DecisionBlock   DecisionKind = "block"
)

type MatchRule struct {
	ProcessNames []string `json:"processNames" yaml:"processNames"`
	Paths        []string `json:"paths" yaml:"paths"`
	PathPrefixes []string `json:"pathPrefixes" yaml:"pathPrefixes"`
	SHA256       []string `json:"sha256" yaml:"sha256"`
	SteamAppIDs  []uint32 `json:"steamAppIds" yaml:"steamAppIds"`
}

type GameProfile struct {
	ID          string    `json:"id" yaml:"id"`
	DisplayName string    `json:"displayName" yaml:"displayName"`
	Enabled     bool      `json:"enabled" yaml:"enabled"`
	Manual      bool      `json:"manual" yaml:"manual"`
	Priority    int       `json:"priority" yaml:"priority"`
	Match       MatchRule `json:"match" yaml:"match"`
	UDPPolicy   UDPPolicy `json:"udpPolicy" yaml:"udpPolicy"`
	TCPPolicy   TCPPolicy `json:"tcpPolicy" yaml:"tcpPolicy"`
}

type SteamPolicy struct {
	Enabled                  bool `json:"enabled" yaml:"enabled"`
	TrackChildProcesses      bool `json:"trackChildProcesses" yaml:"trackChildProcesses"`
	AccelerateGameUDP        bool `json:"accelerateGameUdp" yaml:"accelerateGameUdp"`
	AccelerateSteamDownloads bool `json:"accelerateSteamDownloads" yaml:"accelerateSteamDownloads"`
}

type LauncherPolicy struct {
	Steam SteamPolicy `json:"steam" yaml:"steam"`
}

type Engine struct {
	Profiles  []GameProfile  `json:"profiles"`
	Launchers LauncherPolicy `json:"launchers"`
}

type Decision struct {
	Kind      DecisionKind `json:"kind"`
	UDPPolicy UDPPolicy    `json:"udpPolicy"`
	TCPPolicy TCPPolicy    `json:"tcpPolicy"`
	ProfileID string       `json:"profileId"`
	Reason    string       `json:"reason"`
}

func (e Engine) Decide(proc pidtrack.ProcessInfo, flow pidtrack.FlowKey) Decision {
	for _, profile := range e.sortedProfiles() {
		if profile.Enabled && profile.Manual && profile.Match.Matches(proc) {
			return gameDecision(profile, "manual game profile")
		}
	}

	if e.Launchers.Steam.Enabled && e.Launchers.Steam.TrackChildProcesses && isSteamGameProcess(proc) {
		if flow.Transport == pidtrack.TransportUDP && e.Launchers.Steam.AccelerateGameUDP {
			return Decision{
				Kind:      DecisionGame,
				UDPPolicy: UDPPolicyTGP,
				TCPPolicy: TCPPolicyAuto,
				Reason:    "steam game process",
			}
		}
	}

	for _, profile := range e.sortedProfiles() {
		if profile.Enabled && !profile.Manual && profile.Match.Matches(proc) {
			return gameDecision(profile, "automatic game profile")
		}
	}

	return Decision{
		Kind:      DecisionDefault,
		UDPPolicy: UDPPolicyAuto,
		TCPPolicy: TCPPolicyAuto,
		Reason:    "no routing profile matched",
	}
}

func gameDecision(profile GameProfile, reason string) Decision {
	return Decision{
		Kind:      DecisionGame,
		UDPPolicy: defaultUDPPolicy(profile.UDPPolicy),
		TCPPolicy: defaultTCPPolicy(profile.TCPPolicy),
		ProfileID: profile.ID,
		Reason:    reason,
	}
}

func (e Engine) sortedProfiles() []GameProfile {
	profiles := append([]GameProfile(nil), e.Profiles...)
	sort.SliceStable(profiles, func(i, j int) bool {
		if profiles[i].Manual != profiles[j].Manual {
			return profiles[i].Manual
		}
		return profiles[i].Priority > profiles[j].Priority
	})
	return profiles
}

func defaultUDPPolicy(policy UDPPolicy) UDPPolicy {
	if policy == "" {
		return UDPPolicyTGP
	}
	return policy
}

func defaultTCPPolicy(policy TCPPolicy) TCPPolicy {
	if policy == "" {
		return TCPPolicyAuto
	}
	return policy
}

func (m MatchRule) Matches(proc pidtrack.ProcessInfo) bool {
	if len(m.ProcessNames) > 0 && containsFold(m.ProcessNames, proc.Name) {
		return true
	}
	if len(m.Paths) > 0 && pathEqualsAny(m.Paths, proc.ExecutablePath) {
		return true
	}
	if len(m.PathPrefixes) > 0 && pathHasPrefixAny(m.PathPrefixes, proc.ExecutablePath) {
		return true
	}
	if len(m.SHA256) > 0 && containsFold(m.SHA256, proc.SHA256) {
		return true
	}
	if len(m.SteamAppIDs) > 0 {
		if appID, ok := steamAppID(proc); ok && containsUint32(m.SteamAppIDs, appID) {
			return true
		}
	}
	return false
}

func isSteamGameProcess(proc pidtrack.ProcessInfo) bool {
	name := strings.ToLower(proc.Name)
	if name == "steam.exe" || name == "steamwebhelper.exe" || name == "steamservice.exe" {
		return false
	}

	if _, ok := steamAppID(proc); ok {
		return true
	}

	if strings.Contains(normalizePath(proc.ExecutablePath), "/steamapps/common/") {
		return true
	}

	for _, ancestor := range proc.Ancestors {
		ancestorName := strings.ToLower(ancestor.Name)
		if ancestorName == "steam.exe" || ancestorName == "steam" {
			return true
		}
	}

	return false
}

func steamAppID(proc pidtrack.ProcessInfo) (uint32, bool) {
	if proc.Tags != nil {
		if raw := proc.Tags["steam_app_id"]; raw != "" {
			if parsed, err := strconv.ParseUint(raw, 10, 32); err == nil {
				return uint32(parsed), true
			}
		}
	}

	for i, arg := range proc.CommandLine {
		if strings.EqualFold(arg, "-steam_appid") && i+1 < len(proc.CommandLine) {
			if parsed, err := strconv.ParseUint(proc.CommandLine[i+1], 10, 32); err == nil {
				return uint32(parsed), true
			}
		}
		if strings.HasPrefix(strings.ToLower(arg), "-steam_appid=") {
			raw := strings.TrimPrefix(strings.ToLower(arg), "-steam_appid=")
			if parsed, err := strconv.ParseUint(raw, 10, 32); err == nil {
				return uint32(parsed), true
			}
		}
	}

	return 0, false
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func containsUint32(values []uint32, target uint32) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func pathEqualsAny(values []string, target string) bool {
	normalizedTarget := normalizePath(target)
	for _, value := range values {
		if normalizePath(value) == normalizedTarget {
			return true
		}
	}
	return false
}

func pathHasPrefixAny(prefixes []string, target string) bool {
	normalizedTarget := normalizePath(target)
	for _, prefix := range prefixes {
		if strings.HasPrefix(normalizedTarget, normalizePath(prefix)) {
			return true
		}
	}
	return false
}

func normalizePath(path string) string {
	cleaned := filepath.Clean(path)
	cleaned = filepath.ToSlash(cleaned)
	return strings.ToLower(cleaned)
}
