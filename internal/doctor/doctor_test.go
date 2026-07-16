package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunWithFactsClientJSONSchemaAndStatus(t *testing.T) {
	path := writeClientConfig(t, false)
	report := RunWithFacts(path, PlatformFacts{
		OS:               "linux",
		Arch:             "amd64",
		LinuxTunExists:   true,
		LinuxTunOpenable: true,
		LinuxCAPKnown:    true,
		LinuxCAPNetAdmin: true,
	})

	if report.OverallStatus != StatusOK {
		t.Fatalf("overall_status = %q, want ok; checks=%#v", report.OverallStatus, report.Checks)
	}
	if !report.Config.Valid || report.Mode.Value != "client" || !report.Client.Valid || report.Server.Valid {
		t.Fatalf("unexpected config/mode summary: %#v", report)
	}
	if !report.ClientRequiresTUN || !report.Client.RequiresTUN {
		t.Fatal("client report should require TUN")
	}
	if report.AutoRoute || report.DNSHijack {
		t.Fatalf("unexpected tun flags: auto_route=%v dns_hijack=%v", report.AutoRoute, report.DNSHijack)
	}

	data, err := report.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	var parsed struct {
		OverallStatus string `json:"overall_status"`
		Checks        []struct {
			ID          string `json:"id"`
			Status      string `json:"status"`
			Message     string `json:"message"`
			Remediation string `json:"remediation"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if parsed.OverallStatus != "ok" {
		t.Fatalf("json overall_status = %q", parsed.OverallStatus)
	}
	for _, id := range []string{CheckConfigValid, CheckClientRequiresTUN, CheckSelectiveRoutes, CheckTUNDevicePresent, CheckTUNPrivilege} {
		if !hasCheck(report.Checks, id) {
			t.Fatalf("missing check id %s in %#v", id, report.Checks)
		}
	}
}

func TestRunWithFactsEmptyGameRoutesNeedsNoRouteSupport(t *testing.T) {
	path := writeClientConfig(t, false)
	report := RunWithFacts(path, PlatformFacts{
		OS:               "linux",
		Arch:             "amd64",
		LinuxTunExists:   true,
		LinuxTunOpenable: true,
		LinuxCAPKnown:    true,
		LinuxCAPNetAdmin: true,
	})

	if report.OverallStatus != StatusOK {
		t.Fatalf("overall_status = %q, want ok", report.OverallStatus)
	}
	check := findCheck(report.Checks, CheckSelectiveRoutes)
	if check.Status != StatusOK {
		t.Fatalf("SELECTIVE_ROUTES_SUPPORTED status = %q, want ok", check.Status)
	}
	if !strings.Contains(check.Message, "hostname") || !strings.Contains(check.Message, "resolves it once") || !strings.Contains(check.Message, "pins the approved IP:port set") || check.Remediation != "" {
		t.Fatalf("empty game_routes check does not describe Relay pinning semantics: %#v", check)
	}
}

func TestRunWithFactsIPLiteralRelayIsPinnedDirectly(t *testing.T) {
	path := writeClientConfig(t, false)
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wire = []byte(strings.ReplaceAll(string(wire), "game.example.com:443", "198.51.100.10:443"))
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	report := RunWithFacts(path, PlatformFacts{
		OS:               "linux",
		Arch:             "amd64",
		LinuxTunExists:   true,
		LinuxTunOpenable: true,
		LinuxCAPKnown:    true,
		LinuxCAPNetAdmin: true,
	})
	check := findCheck(report.Checks, CheckSelectiveRoutes)
	if !strings.Contains(check.Message, "IP literal") || !strings.Contains(check.Message, "pins that IP:port directly") || strings.Contains(check.Message, "resolves") {
		t.Fatalf("IP literal check does not describe direct pinning: %#v", check)
	}
}

func TestRunWithFactsNonEmptyGameRoutesMatchPlatformSupport(t *testing.T) {
	path := writeClientConfig(t, false, "203.0.113.0/24")
	tests := []struct {
		name       string
		facts      PlatformFacts
		wantStatus Status
		wantText   string
	}{
		{
			name: "Windows supported",
			facts: PlatformFacts{
				OS:                "windows",
				Arch:              "amd64",
				WintunDLLFound:    true,
				WindowsAdminKnown: true,
				WindowsAdmin:      true,
			},
			wantStatus: StatusOK,
			wantText:   "supports transactional installation",
		},
		{
			name: "Linux fails closed",
			facts: PlatformFacts{
				OS:               "linux",
				Arch:             "amd64",
				LinuxTunExists:   true,
				LinuxTunOpenable: true,
				LinuxCAPKnown:    true,
				LinuxCAPNetAdmin: true,
			},
			wantStatus: StatusError,
			wantText:   "unsupported on linux; client startup fails closed before TUN creation",
		},
		{
			name:       "macOS fails closed",
			facts:      PlatformFacts{OS: "darwin", Arch: "arm64", DarwinIfconfigFound: true, DarwinIfconfigPath: "/sbin/ifconfig"},
			wantStatus: StatusError,
			wantText:   "unsupported on darwin; client startup fails closed before TUN creation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := RunWithFacts(path, tt.facts)
			check := findCheck(report.Checks, CheckSelectiveRoutes)
			if check.Status != tt.wantStatus || !strings.Contains(check.Message, tt.wantText) {
				t.Fatalf("selective route check = %#v", check)
			}
			if tt.wantStatus == StatusError && report.OverallStatus != StatusError {
				t.Fatalf("overall_status = %q, want error", report.OverallStatus)
			}
		})
	}
}

func TestRunWithFactsAutoRouteTrueFailsConfigValidation(t *testing.T) {
	path := writeClientConfig(t, true)
	report := RunWithFacts(path, PlatformFacts{OS: "linux", Arch: "amd64"})
	if report.OverallStatus != StatusError || report.Config.Valid {
		t.Fatalf("auto_route=true report must fail config validation: %#v", report)
	}
}

func TestRunWithFactsInvalidConfigReturnsJSONErrorReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"mode":"client"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	report := RunWithFacts(path, PlatformFacts{OS: "linux", Arch: "amd64"})
	if report.OverallStatus != StatusError {
		t.Fatalf("overall_status = %q, want error", report.OverallStatus)
	}
	if report.Config.Valid {
		t.Fatal("config should be invalid")
	}
	if findCheck(report.Checks, CheckConfigValid).Status != StatusError {
		t.Fatalf("CONFIG_VALID should be error: %#v", report.Checks)
	}
	if _, err := report.JSON(); err != nil {
		t.Fatalf("invalid config report should still marshal: %v", err)
	}
}

func TestLinuxChecksArePureAndReportDeviceAndCapability(t *testing.T) {
	checks := linuxChecks(PlatformFacts{
		OS:               "linux",
		LinuxTunExists:   false,
		LinuxCAPKnown:    true,
		LinuxCAPNetAdmin: false,
	})

	if findCheck(checks, CheckTUNDevicePresent).Status != StatusError {
		t.Fatalf("missing /dev/net/tun should be error: %#v", checks)
	}
	priv := findCheck(checks, CheckTUNPrivilege)
	if priv.Status != StatusError || !strings.Contains(priv.Message, "CAP_NET_ADMIN") {
		t.Fatalf("missing CAP_NET_ADMIN should be error with remediation context: %#v", priv)
	}
}

func TestWindowsChecksArePureAndReportDLLAndElevation(t *testing.T) {
	checks := windowsChecks(PlatformFacts{
		OS:                "windows",
		WintunDLLFound:    false,
		WindowsAdminKnown: true,
		WindowsAdmin:      false,
	})

	if findCheck(checks, CheckWintunDLLPresent).Status != StatusError {
		t.Fatalf("missing wintun.dll should be error: %#v", checks)
	}
	priv := findCheck(checks, CheckTUNPrivilege)
	if priv.Status != StatusError || !strings.Contains(priv.Message, "Administrator") {
		t.Fatalf("non-elevated Windows should be error: %#v", priv)
	}
}

func TestWindowsChecksReportFoundDLLWithoutLoading(t *testing.T) {
	checks := windowsChecks(PlatformFacts{
		OS:                "windows",
		WintunDLLFound:    true,
		WintunDLLPath:     `C:\Tachyon\wintun.dll`,
		WindowsAdminKnown: true,
		WindowsAdmin:      true,
	})

	dll := findCheck(checks, CheckWintunDLLPresent)
	if dll.Status != StatusOK {
		t.Fatalf("found wintun.dll should be ok: %#v", dll)
	}
	if strings.Contains(strings.ToLower(dll.Message), "loaded") {
		t.Fatalf("WINTUN_DLL_PRESENT must not imply DLL loading: %q", dll.Message)
	}
	if findCheck(checks, CheckTUNPrivilege).Status != StatusOK {
		t.Fatalf("elevated Windows should pass privilege check: %#v", checks)
	}
}

func TestWindowsDoctorImplementationDoesNotLoadDLL(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "platform_windows.go"))
	if err != nil {
		t.Fatalf("read platform_windows.go: %v", err)
	}
	source := string(data)
	for _, forbidden := range []string{"LoadDLL", "LoadLibrary"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("doctor Windows preflight must not call %s", forbidden)
		}
	}
}

func TestDarwinChecksArePureAndReadOnlyWarning(t *testing.T) {
	checks := darwinChecks(PlatformFacts{
		OS:                  "darwin",
		DarwinIfconfigFound: true,
		DarwinIfconfigPath:  "/sbin/ifconfig",
	})

	priv := findCheck(checks, CheckTUNPrivilege)
	if priv.Status != StatusWarn || !strings.Contains(priv.Message, "read-only") {
		t.Fatalf("macOS TUN privilege check should be read-only warning: %#v", priv)
	}
	if findCheck(checks, CheckIfconfigPresent).Status != StatusOK {
		t.Fatalf("ifconfig should be ok: %#v", checks)
	}
	for _, check := range checks {
		if strings.Contains(check.Message, "/sbin/route") || strings.Contains(check.Message, "auto_route") {
			t.Fatalf("Darwin check contains an obsolete route hint: %#v", check)
		}
	}
}

func TestReadCapNetAdmin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte("Name:\ttachyon\nCapEff:\t0000000000001000\n"), 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}
	hasCap, known, err := readCapNetAdmin(path)
	if err != nil {
		t.Fatalf("read cap: %v", err)
	}
	if !known || !hasCap {
		t.Fatalf("CAP_NET_ADMIN should be known and present, known=%v has=%v", known, hasCap)
	}
}

func writeClientConfig(t *testing.T, autoRoute bool, gameRoutes ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.json")
	autoRouteValue := "false"
	if autoRoute {
		autoRouteValue = "true"
	}
	routesJSON, err := json.Marshal(gameRoutes)
	if err != nil {
		t.Fatalf("marshal game routes: %v", err)
	}
	data := `{
  "mode": "client",
  "client": {
    "tun": {
      "auto_route": ` + autoRouteValue + `,
      "dns_hijack": false,
      "game_routes": ` + string(routesJSON) + `
    },
    "proxy": {
      "server_addr": "game.example.com:443"
    }
  },
  "tgp": {
    "fec": {
      "data_shards": 4
    },
    "pacing": {
      "initial_rate_pps": 128
    }
  }
}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func hasCheck(checks []Check, id string) bool {
	return findCheck(checks, id).ID != ""
}

func findCheck(checks []Check, id string) Check {
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	return Check{}
}
