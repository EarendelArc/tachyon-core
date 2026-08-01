//go:build windows

package helper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsTestServerReadyFilePublishesListenerIdentity(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	directory := filepath.Join(programData, "Tachyon", "Harness", "0123456789abcdef0123456789abcdef")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "core-ready.json")
	pipeName := `\\.\pipe\Tachyon\ready-test`
	if err := writeTestServerReady(path, pipeName); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ready testServerReady
	if err := json.Unmarshal(data, &ready); err != nil {
		t.Fatal(err)
	}
	if ready.Stage != "listening" || ready.PID != os.Getpid() || ready.Pipe != pipeName {
		t.Fatalf("ready identity = %+v", ready)
	}
	if err := writeTestServerReady(path, pipeName); err == nil {
		t.Fatal("existing ready file was overwritten")
	}
	if _, err := os.Stat(filepath.Join(directory, "core-ready.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary ready file was not cleaned up: %v", err)
	}
}

func TestWindowsTestServerReadyFileRejectsUnmanagedPath(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	path := filepath.Join(programData, "outside", "core-ready.json")
	if err := writeTestServerReady(path, `\\.\pipe\Tachyon\ready-test`); err == nil {
		t.Fatal("unmanaged ready path was accepted")
	}
}
