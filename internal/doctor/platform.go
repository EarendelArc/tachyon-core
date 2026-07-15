package doctor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type PlatformFacts struct {
	OS   string
	Arch string

	WintunDLLFound    bool
	WintunDLLPath     string
	WindowsAdminKnown bool
	WindowsAdmin      bool
	WindowsAdminError string

	LinuxTunExists   bool
	LinuxTunOpenable bool
	LinuxTunError    string
	LinuxCAPKnown    bool
	LinuxCAPNetAdmin bool
	LinuxCAPError    string

	DarwinIfconfigFound bool
	DarwinIfconfigPath  string
}

func CurrentPlatformFacts() PlatformFacts {
	facts := PlatformFacts{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	switch runtime.GOOS {
	case "windows":
		fillWindowsFacts(&facts)
	case "linux":
		fillLinuxFacts(&facts)
	case "darwin":
		fillDarwinFacts(&facts)
	}
	return facts
}

func fillLinuxFacts(facts *PlatformFacts) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			facts.LinuxTunError = err.Error()
		}
	} else {
		facts.LinuxTunExists = true
	}

	if facts.LinuxTunExists {
		file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
		if err != nil {
			facts.LinuxTunError = err.Error()
		} else {
			facts.LinuxTunOpenable = true
			_ = file.Close()
		}
	}

	hasCap, known, err := readCapNetAdmin("/proc/self/status")
	facts.LinuxCAPKnown = known
	facts.LinuxCAPNetAdmin = hasCap
	if err != nil {
		facts.LinuxCAPError = err.Error()
	}
}

func fillDarwinFacts(facts *PlatformFacts) {
	if path, err := exec.LookPath("ifconfig"); err == nil {
		facts.DarwinIfconfigFound = true
		facts.DarwinIfconfigPath = path
	} else if _, err := os.Stat("/sbin/ifconfig"); err == nil {
		facts.DarwinIfconfigFound = true
		facts.DarwinIfconfigPath = "/sbin/ifconfig"
	}
}

func findDLLCandidate(name string) (string, bool) {
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

func readCapNetAdmin(path string) (hasCap bool, known bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		value, err := strconv.ParseUint(raw, 16, 64)
		if err != nil {
			return false, true, fmt.Errorf("parse CapEff %q: %w", raw, err)
		}
		const capNetAdmin = 12
		return value&(uint64(1)<<capNetAdmin) != 0, true, nil
	}
	return false, false, fmt.Errorf("CapEff not found")
}

func platformChecks(facts PlatformFacts, requiresTUN bool) []Check {
	if !requiresTUN {
		return []Check{
			{
				ID:          CheckTUNPrivilege,
				Status:      StatusSkipped,
				Message:     "TUN readiness checks are skipped because this config is not client mode.",
				Remediation: "",
			},
		}
	}

	switch facts.OS {
	case "windows":
		return windowsChecks(facts)
	case "linux":
		return linuxChecks(facts)
	case "darwin":
		return darwinChecks(facts)
	default:
		return []Check{
			{
				ID:          CheckTUNPrivilege,
				Status:      StatusWarn,
				Message:     fmt.Sprintf("No read-only TUN readiness checker is implemented for %s/%s.", facts.OS, facts.Arch),
				Remediation: "Validate TUN driver availability and privileges manually before starting client mode.",
			},
		}
	}
}

func windowsChecks(facts PlatformFacts) []Check {
	checks := make([]Check, 0, 2)
	if facts.WintunDLLFound {
		checks = append(checks, Check{
			ID:          CheckWintunDLLPresent,
			Status:      StatusOK,
			Message:     fmt.Sprintf("wintun.dll was found at %s.", emptyAsUnknown(facts.WintunDLLPath)),
			Remediation: "",
		})
	} else {
		checks = append(checks, Check{
			ID:          CheckWintunDLLPresent,
			Status:      StatusError,
			Message:     "wintun.dll was not found next to tachyon-core.exe or on PATH.",
			Remediation: "Ship wintun.dll with tachyon-core.exe or add its directory to PATH before starting client mode.",
		})
	}

	switch {
	case facts.WindowsAdminKnown && facts.WindowsAdmin:
		checks = append(checks, Check{
			ID:          CheckTUNPrivilege,
			Status:      StatusOK,
			Message:     "The current Windows process appears to be elevated.",
			Remediation: "",
		})
	case facts.WindowsAdminKnown:
		checks = append(checks, Check{
			ID:          CheckTUNPrivilege,
			Status:      StatusError,
			Message:     "The current Windows process does not appear to be elevated; Wintun adapter creation requires Administrator privileges.",
			Remediation: "Start Prism/Core elevated or install a service path that launches Core with Administrator privileges.",
		})
	default:
		checks = append(checks, Check{
			ID:          CheckTUNPrivilege,
			Status:      StatusWarn,
			Message:     fmt.Sprintf("Windows elevation status could not be determined: %s.", emptyAsUnknown(facts.WindowsAdminError)),
			Remediation: "If client startup fails creating the Wintun adapter, rerun elevated.",
		})
	}
	return checks
}

func linuxChecks(facts PlatformFacts) []Check {
	checks := make([]Check, 0, 2)
	if facts.LinuxTunExists {
		status := StatusOK
		message := "/dev/net/tun exists."
		remediation := ""
		if !facts.LinuxTunOpenable {
			status = StatusError
			message = fmt.Sprintf("/dev/net/tun exists but cannot be opened read/write by this process: %s.", emptyAsUnknown(facts.LinuxTunError))
			remediation = "Fix /dev/net/tun permissions or start Core with an account that can open the TUN clone device."
		}
		checks = append(checks, Check{
			ID:          CheckTUNDevicePresent,
			Status:      status,
			Message:     message,
			Remediation: remediation,
		})
	} else {
		checks = append(checks, Check{
			ID:          CheckTUNDevicePresent,
			Status:      StatusError,
			Message:     fmt.Sprintf("/dev/net/tun is not available: %s.", emptyAsUnknown(facts.LinuxTunError)),
			Remediation: "Load or enable the tun kernel module and ensure /dev/net/tun exists before starting client mode.",
		})
	}

	switch {
	case facts.LinuxCAPKnown && facts.LinuxCAPNetAdmin:
		checks = append(checks, Check{
			ID:          CheckTUNPrivilege,
			Status:      StatusOK,
			Message:     "CAP_NET_ADMIN is present in the current effective capability set.",
			Remediation: "",
		})
	case facts.LinuxCAPKnown:
		checks = append(checks, Check{
			ID:          CheckTUNPrivilege,
			Status:      StatusError,
			Message:     "CAP_NET_ADMIN is not present in the current effective capability set; creating/configuring a TUN interface will fail.",
			Remediation: "Run Core with CAP_NET_ADMIN or equivalent privileges, for example via a supervised service configured with the required capability.",
		})
	default:
		checks = append(checks, Check{
			ID:          CheckTUNPrivilege,
			Status:      StatusWarn,
			Message:     fmt.Sprintf("Could not determine CAP_NET_ADMIN from /proc/self/status: %s.", emptyAsUnknown(facts.LinuxCAPError)),
			Remediation: "Ensure the process has CAP_NET_ADMIN or root-equivalent network administration privileges.",
		})
	}
	return checks
}

func darwinChecks(facts PlatformFacts) []Check {
	checks := []Check{
		{
			ID:          CheckTUNPrivilege,
			Status:      StatusWarn,
			Message:     "macOS utun readiness is checked read-only; Core may still need permission to create utun and configure it with ifconfig at startup.",
			Remediation: "If startup fails, run through Prism's privileged helper, Network Extension path, or another approved elevation flow.",
		},
	}
	if facts.DarwinIfconfigFound {
		checks = append(checks, Check{
			ID:          CheckIfconfigPresent,
			Status:      StatusOK,
			Message:     fmt.Sprintf("ifconfig is available at %s.", facts.DarwinIfconfigPath),
			Remediation: "",
		})
	} else {
		checks = append(checks, Check{
			ID:          CheckIfconfigPresent,
			Status:      StatusWarn,
			Message:     "ifconfig was not found in PATH or /sbin/ifconfig.",
			Remediation: "Ensure Core can execute /sbin/ifconfig when client mode configures utun addresses and MTU.",
		})
	}
	return checks
}

func emptyAsUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}
