package helper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticFileKeepsExclusiveHandleAndRewritesInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "helper-health.json")
	diagnostic, err := openDiagnosticFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openDiagnosticFile(path, true); err == nil {
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
