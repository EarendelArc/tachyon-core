//go:build windows

package helper

import (
	"os"
	"path/filepath"
	"testing"
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

func TestHarnessDiagnosticFileAllowsAuthorizedReadWhileWriterIsOpen(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	path := filepath.Join(programData, "Tachyon", "Harness", "0123456789abcdef0123456789abcdef", "helper-health.json")
	diagnostic, err := openDiagnosticFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer diagnostic.Close()
	if err := diagnostic.Write([]byte(`{"status":"not_ready"}`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("authorized read while helper owns the writer handle: %v", err)
	}
	if string(data) != `{"status":"not_ready"}` {
		t.Fatalf("diagnostic data = %q", data)
	}
}
