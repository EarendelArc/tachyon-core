package app

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestXrayBinaryPathUsesInstallDir(t *testing.T) {
	path := xrayBinaryPath(filepath.Join("tmp", "xray"))
	want := filepath.Join("tmp", "xray", "xray")
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	if err := writeFileAtomic(path, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatalf("write atomic: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("unexpected data: %s", data)
	}
}
