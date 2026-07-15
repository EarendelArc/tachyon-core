// Package doctor provides read-only preflight diagnostics for Tachyon Core.
package doctor

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/tachyon-space/tachyon-core/internal/config"
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusError   Status = "error"
	StatusSkipped Status = "skipped"
)

const (
	CheckConfigValid       = "CONFIG_VALID"
	CheckClientRequiresTUN = "CLIENT_REQUIRES_TUN"
	CheckWintunDLLPresent  = "WINTUN_DLL_PRESENT"
	CheckTUNDevicePresent  = "TUN_DEVICE_PRESENT"
	CheckTUNPrivilege      = "TUN_PRIVILEGE"
	CheckSelectiveRoutes   = "SELECTIVE_ROUTES_SUPPORTED"
	CheckIfconfigPresent   = "IFCONFIG_PRESENT"
)

type Report struct {
	OverallStatus     Status        `json:"overall_status"`
	Mode              ModeSummary   `json:"mode"`
	Config            ConfigSummary `json:"config"`
	Client            ClientSummary `json:"client"`
	Server            ServerSummary `json:"server"`
	ClientRequiresTUN bool          `json:"client_requires_tun"`
	AutoRoute         bool          `json:"auto_route"`
	DNSHijack         bool          `json:"dns_hijack"`
	GameRoutes        []string      `json:"game_routes,omitempty"`
	Platform          Platform      `json:"platform"`
	Checks            []Check       `json:"checks"`
}

type ModeSummary struct {
	Value string `json:"value"`
	Valid bool   `json:"valid"`
}

type ConfigSummary struct {
	Path  string `json:"path"`
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

type ClientSummary struct {
	Applicable  bool     `json:"applicable"`
	Valid       bool     `json:"valid"`
	RequiresTUN bool     `json:"requires_tun"`
	AutoRoute   bool     `json:"auto_route"`
	DNSHijack   bool     `json:"dns_hijack"`
	GameRoutes  []string `json:"game_routes,omitempty"`
}

type ServerSummary struct {
	Applicable bool `json:"applicable"`
	Valid      bool `json:"valid"`
}

type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Check struct {
	ID          string `json:"id"`
	Status      Status `json:"status"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// Run loads the config and evaluates read-only platform readiness checks.
func Run(configPath string) Report {
	return RunWithFacts(configPath, CurrentPlatformFacts())
}

func RunWithFacts(configPath string, facts PlatformFacts) Report {
	if facts.OS == "" {
		facts.OS = runtime.GOOS
	}
	if facts.Arch == "" {
		facts.Arch = runtime.GOARCH
	}

	report := Report{
		OverallStatus: StatusOK,
		Config: ConfigSummary{
			Path: configPath,
		},
		Platform: Platform{
			OS:   facts.OS,
			Arch: facts.Arch,
		},
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		report.Config.Error = err.Error()
		report.Checks = append(report.Checks, Check{
			ID:          CheckConfigValid,
			Status:      StatusError,
			Message:     fmt.Sprintf("Config %q is invalid: %v.", configPath, err),
			Remediation: "Fix the config file, then rerun tachyon-core doctor --config <path> --json.",
		})
		report.Checks = append(report.Checks, Check{
			ID:          CheckClientRequiresTUN,
			Status:      StatusSkipped,
			Message:     "Client TUN requirement cannot be determined until the config is valid.",
			Remediation: "Fix CONFIG_VALID first.",
		})
		report.finalize()
		return report
	}

	report.Config.Valid = true
	report.Mode = ModeSummary{Value: string(cfg.Mode), Valid: cfg.Mode == config.ModeClient || cfg.Mode == config.ModeServer}
	report.Client.Applicable = cfg.Mode == config.ModeClient
	report.Client.Valid = cfg.Mode == config.ModeClient
	report.Server.Applicable = cfg.Mode == config.ModeServer
	report.Server.Valid = cfg.Mode == config.ModeServer
	report.Checks = append(report.Checks, Check{
		ID:          CheckConfigValid,
		Status:      StatusOK,
		Message:     fmt.Sprintf("Config %q is valid for %s mode.", configPath, cfg.Mode),
		Remediation: "",
	})

	if cfg.Mode == config.ModeClient {
		report.ClientRequiresTUN = true
		report.AutoRoute = cfg.Client.TUN.AutoRoute
		report.DNSHijack = cfg.Client.TUN.DNSHijack
		report.Client.RequiresTUN = true
		report.Client.AutoRoute = cfg.Client.TUN.AutoRoute
		report.Client.DNSHijack = cfg.Client.TUN.DNSHijack
		report.GameRoutes = append([]string(nil), cfg.Client.TUN.GameRoutes...)
		report.Client.GameRoutes = append([]string(nil), cfg.Client.TUN.GameRoutes...)
		report.Checks = append(report.Checks, Check{
			ID:          CheckClientRequiresTUN,
			Status:      StatusOK,
			Message:     "Client mode starts a TUN device before the packet pipeline.",
			Remediation: "",
		})
		report.Checks = append(report.Checks, selectiveRoutesCheck(facts.OS, cfg.Client.TUN.GameRoutes))
		report.Checks = append(report.Checks, platformChecks(facts, true)...)
	} else {
		report.Checks = append(report.Checks, Check{
			ID:          CheckClientRequiresTUN,
			Status:      StatusSkipped,
			Message:     "Server mode does not create a client TUN device.",
			Remediation: "",
		})
		report.Checks = append(report.Checks, Check{
			ID:          CheckSelectiveRoutes,
			Status:      StatusSkipped,
			Message:     "Selective game routes are only applicable to client mode.",
			Remediation: "",
		})
		report.Checks = append(report.Checks, platformChecks(facts, false)...)
	}

	report.finalize()
	return report
}

func selectiveRoutesCheck(goos string, routes []string) Check {
	if len(routes) == 0 {
		return Check{
			ID:          CheckSelectiveRoutes,
			Status:      StatusOK,
			Message:     "client.tun.game_routes is empty; Core will not resolve the Relay or install OS destination routes during startup.",
			Remediation: "",
		}
	}
	if goos == "windows" {
		return Check{
			ID:          CheckSelectiveRoutes,
			Status:      StatusOK,
			Message:     fmt.Sprintf("Windows supports transactional installation of %d configured selective game route(s).", len(routes)),
			Remediation: "",
		}
	}
	return Check{
		ID:          CheckSelectiveRoutes,
		Status:      StatusError,
		Message:     fmt.Sprintf("client.tun.game_routes is non-empty, but selective route transactions are unsupported on %s; client startup fails closed before TUN creation.", goos),
		Remediation: "Leave client.tun.game_routes empty on this platform or run the client on Windows until equivalent transactional route support is implemented.",
	}
}

func (r *Report) finalize() {
	status := StatusOK
	for _, check := range r.Checks {
		switch check.Status {
		case StatusError:
			r.OverallStatus = StatusError
			return
		case StatusWarn:
			status = StatusWarn
		}
	}
	r.OverallStatus = status
}

func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
