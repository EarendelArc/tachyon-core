//go:build !windows

package helper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticFileKeepsExclusiveHandleAndRewritesInPlace(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	path := filepath.Join(programData, "Tachyon", "Harness", "0123456789abcdef0123456789abcdef", "helper-health.json")
	diagnostic, err := openDiagnosticFile(path, true, "S-1-5-80-1-2-3-4-5", "S-1-5-21-1-2-3-4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openDiagnosticFile(path, true, "S-1-5-80-1-2-3-4-5", "S-1-5-21-1-2-3-4"); err == nil {
		_ = diagnostic.Close()
		t.Fatal("second diagnostic handle unexpectedly opened")
	}
	if err := diagnostic.Write([]byte(`{"state":"first"}`)); err != nil {
		_ = diagnostic.Close()
		t.Fatal(err)
	}
	if err := diagnostic.Write([]byte(`{"state":"second"}`)); err != nil {
		_ = diagnostic.Close()
		t.Fatal(err)
	}
	if err := diagnostic.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"state":"second"}` {
		t.Fatalf("diagnostic data = %q", data)
	}
}
