//go:build !windows && !linux && !darwin

package helper

import (
	"fmt"
	"os"
	"path/filepath"
)

func defaultDiagnosticPath() string { return ".tachyon/helper-health.json" }

func validateDiagnosticPath(path string, override bool) error {
	if path == "" {
		return fmt.Errorf("diagnostic path is required")
	}
	return nil
}

func secureDiagnosticPath(string) error { return nil }

func writeDiagnosticAtomic(path string, data []byte, _ bool) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(parent, 0o700)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(temporary, 0o600)
	return os.Rename(temporary, path)
}
