//go:build linux || darwin

package helper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func defaultDiagnosticPath() string { return ".tachyon/helper-health.json" }

func validateDiagnosticPath(path string, _ bool) error {
	if path == "" {
		return fmt.Errorf("diagnostic path is required")
	}
	return nil
}

func secureDiagnosticPath(path string) error {
	return os.Chmod(path, 0o700)
}

func writeDiagnosticAtomic(path string, data []byte, _ bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve diagnostic path: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create helper diagnostic directory: %w", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return fmt.Errorf("protect helper diagnostic directory: %w", err)
	}
	directory, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open helper diagnostic directory: %w", err)
	}
	defer unix.Close(directory)
	name := filepath.Base(absolute)
	var existing unix.Stat_t
	if err := unix.Fstatat(directory, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT == unix.S_IFLNK {
			return fmt.Errorf("diagnostic file is a symlink")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect diagnostic file: %w", err)
	}
	temporary := fmt.Sprintf(".%s.tmp.%d", name, os.Getpid())
	fd, err := unix.Openat(directory, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create diagnostic temporary file: %w", err)
	}
	writeErr := func() error {
		if err := unix.Fchmod(fd, 0o600); err != nil {
			return err
		}
		for len(data) > 0 {
			written, err := unix.Write(fd, data)
			if err != nil {
				return err
			}
			if written == 0 {
				return fmt.Errorf("diagnostic write made no progress")
			}
			data = data[written:]
		}
		return unix.Fsync(fd)
	}()
	closeErr := unix.Close(fd)
	if writeErr != nil || closeErr != nil {
		_ = unix.Unlinkat(directory, temporary, 0)
		return fmt.Errorf("write diagnostic temporary file: %w", errors.Join(writeErr, closeErr))
	}
	if err := unix.Renameat(directory, temporary, directory, name); err != nil {
		_ = unix.Unlinkat(directory, temporary, 0)
		return fmt.Errorf("atomically replace diagnostic: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("flush diagnostic directory: %w", err)
	}
	return nil
}
