//go:build linux || darwin

package helper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

func defaultDiagnosticPath() string { return ".tachyon/helper-health.json" }

func validateDiagnosticPath(path string, _ bool) error {
	if path == "" {
		return fmt.Errorf("diagnostic path is required")
	}
	return nil
}

type unixDiagnosticFile struct {
	mu sync.Mutex
	fd int
}

func openDiagnosticFile(path string, _ bool, _ string, _ string) (diagnosticFile, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve diagnostic path: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create helper diagnostic directory: %w", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, fmt.Errorf("protect helper diagnostic directory: %w", err)
	}
	directory, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open helper diagnostic directory: %w", err)
	}
	name := filepath.Base(absolute)
	fd, err := unix.Openat(directory, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	closeDirErr := unix.Close(directory)
	if err != nil || closeDirErr != nil {
		if err == nil {
			err = closeDirErr
		}
		return nil, fmt.Errorf("open fixed diagnostic file: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect fixed diagnostic file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, errors.New("diagnostic file must be a regular file")
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("protect fixed diagnostic file: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("lock fixed diagnostic file: %w", err)
	}
	return &unixDiagnosticFile{fd: fd}, nil
}

func (file *unixDiagnosticFile) Write(data []byte) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.fd < 0 {
		return errors.New("diagnostic file is closed")
	}
	if _, err := unix.Seek(file.fd, 0, 0); err != nil {
		return fmt.Errorf("seek diagnostic file: %w", err)
	}
	if err := unix.Ftruncate(file.fd, 0); err != nil {
		return fmt.Errorf("truncate diagnostic file: %w", err)
	}
	for len(data) > 0 {
		written, err := unix.Write(file.fd, data)
		if err != nil {
			return fmt.Errorf("write diagnostic file: %w", err)
		}
		if written == 0 {
			return errors.New("diagnostic write made no progress")
		}
		data = data[written:]
	}
	if err := unix.Fsync(file.fd); err != nil {
		return fmt.Errorf("flush diagnostic file: %w", err)
	}
	return nil
}

func (file *unixDiagnosticFile) Close() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.fd < 0 {
		return nil
	}
	err := unix.Close(file.fd)
	file.fd = -1
	return err
}
