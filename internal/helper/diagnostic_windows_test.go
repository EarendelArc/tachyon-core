//go:build windows

package helper

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHarnessDiagnosticPathPolicyRejectsEscapesAndUnexpectedFiles(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	valid := filepath.Join(programData, "Tachyon", "Harness", "0123456789abcdef0123456789abcdef", "helper-health.json")
	if err := validateDiagnosticPath(valid, true); err != nil {
		t.Fatalf("valid harness path rejected: %v", err)
	}
	for _, path := range []string{
		filepath.Join(programData, "Tachyon", "Harness", "not-a-guid", "helper-health.json"),
		filepath.Join(programData, "Tachyon", "Harness", "0123456789abcdef0123456789abcdef", "other.json"),
		filepath.Join(programData, "Tachyon", "Harness", "0123456789abcdef0123456789abcdef", "..", "helper-health.json"),
		filepath.Join(t.TempDir(), "helper-health.json"),
	} {
		if err := validateDiagnosticPath(path, true); err == nil {
			t.Fatalf("unsafe harness path accepted: %q", path)
		}
	}
}

func TestDiagnosticAccessMasksNeverRequestWriteDAC(t *testing.T) {
	if diagnosticDirectoryAccess&windows.WRITE_DAC != 0 || diagnosticFileAccess&windows.WRITE_DAC != 0 {
		t.Fatalf("diagnostic handles must never request WRITE_DAC: directory=%#x file=%#x", diagnosticDirectoryAccess, diagnosticFileAccess)
	}
	if diagnosticFileAccess&(windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA) != windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA {
		t.Fatalf("diagnostic file mask lacks required write access: %#x", diagnosticFileAccess)
	}
	if diagnosticDirectoryAccess&(windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA) != 0 {
		t.Fatalf("diagnostic directory mask grants data write access: %#x", diagnosticDirectoryAccess)
	}
	forbidden := windows.ACCESS_MASK(windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	if diagnosticDirectoryAccess&forbidden != 0 || diagnosticFileAccess&forbidden != 0 {
		t.Fatalf("diagnostic handles request more than their read/write contract: directory=%#x file=%#x", diagnosticDirectoryAccess, diagnosticFileAccess)
	}
}

func TestDiagnosticSecurityErrorMapsToSCMAccessDenied(t *testing.T) {
	serviceSpecific, code := helperServiceExitCode(newDiagnosticSecurityError("ACL mismatch"))
	if serviceSpecific || code != uint32(windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("security exit = service-specific:%t code:%d", serviceSpecific, code)
	}
	serviceSpecific, code = helperServiceExitCode(errors.New("ordinary failure"))
	if !serviceSpecific || code != 1 {
		t.Fatalf("ordinary exit = service-specific:%t code:%d", serviceSpecific, code)
	}
}

func TestExpectedDiagnosticSecurityIsBoundToServiceSID(t *testing.T) {
	first, err := expectedDiagnosticSecurity("S-1-5-80-1-2-3-4-5", "S-1-5-21-1-2-3-4", true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := expectedDiagnosticSecurity("S-1-5-80-5-4-3-2-1", "S-1-5-21-1-2-3-4", true)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() == second.String() {
		t.Fatal("diagnostic ACL is not bound to the service SID")
	}
	third, err := expectedDiagnosticSecurity("S-1-5-80-1-2-3-4-5", "S-1-5-21-4-3-2-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() == third.String() {
		t.Fatal("diagnostic ACL is not bound to the installer owner SID")
	}
}
