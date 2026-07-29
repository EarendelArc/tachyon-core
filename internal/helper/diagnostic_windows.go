//go:build windows

package helper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func defaultDiagnosticPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Tachyon", "helper-health.json")
}

func validateDiagnosticPath(path string, override bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid diagnostic path: %w", err)
	}
	if !override && !strings.EqualFold(filepath.Clean(absolute), filepath.Clean(defaultDiagnosticPath())) {
		return fmt.Errorf("diagnostic path must be the protected ProgramData path")
	}
	return rejectDiagnosticReparsePoints(absolute)
}

func rejectDiagnosticReparsePoints(path string) error {
	volume := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, volume)
	current := volume + string(filepath.Separator)
	parts := strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' || r == '/' })
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("inspect diagnostic path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("diagnostic path contains a symlink")
		}
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil {
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
				continue
			}
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("diagnostic path contains a reparse point")
		}
	}
	return nil
}

func secureDiagnosticPath(path string) error {
	securityDescriptor, err := windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;SU)")
	if err != nil {
		return fmt.Errorf("build diagnostic ACL: %w", err)
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return fmt.Errorf("read diagnostic ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply diagnostic ACL: %w", err)
	}
	return nil
}
