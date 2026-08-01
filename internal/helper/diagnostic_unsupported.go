//go:build !windows && !linux && !darwin

package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

func defaultDiagnosticPath() string { return ".tachyon/helper-health.json" }

func validateDiagnosticPath(path string, _ bool) error {
	if path == "" {
		return fmt.Errorf("diagnostic path is required")
	}
	return nil
}

type portableDiagnosticFile struct {
	mu   sync.Mutex
	file *os.File
}

func openDiagnosticFile(path string, _ bool, _ string, _ string) (diagnosticFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &portableDiagnosticFile{file: file}, nil
}

func (file *portableDiagnosticFile) Write(data []byte) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.file == nil {
		return fmt.Errorf("diagnostic file is closed")
	}
	if err := file.file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.file.Seek(0, 0); err != nil {
		return err
	}
	if _, err := file.file.Write(data); err != nil {
		return err
	}
	return file.file.Sync()
}

func (file *portableDiagnosticFile) Close() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.file == nil {
		return nil
	}
	err := file.file.Close()
	file.file = nil
	return err
}
