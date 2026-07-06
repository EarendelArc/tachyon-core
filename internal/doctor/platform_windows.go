//go:build windows

package doctor

import (
	"golang.org/x/sys/windows"
)

func fillWindowsFacts(facts *PlatformFacts) {
	if path, ok := findDLLCandidate("wintun.dll"); ok {
		facts.WintunDLLFound = true
		facts.WintunDLLPath = path
	}

	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		facts.WindowsAdminError = err.Error()
		return
	}
	defer token.Close()
	facts.WindowsAdminKnown = true
	facts.WindowsAdmin = token.IsElevated()
}
