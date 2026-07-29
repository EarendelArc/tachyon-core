//go:build !windows

package helper

import "fmt"

func defaultDiagnosticPath() string { return ".tachyon/helper-health.json" }

func validateDiagnosticPath(path string, override bool) error {
	if path == "" {
		return fmt.Errorf("diagnostic path is required")
	}
	return nil
}

func secureDiagnosticPath(string) error { return nil }
