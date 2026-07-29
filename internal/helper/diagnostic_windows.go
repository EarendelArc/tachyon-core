//go:build windows

package helper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

func writeDiagnosticAtomic(path string, data []byte, override bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve diagnostic path: %w", err)
	}
	if err := validateDiagnosticPath(absolute, override); err != nil {
		return err
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create helper diagnostic directory: %w", err)
	}
	if err := secureDiagnosticPath(parent); err != nil {
		return err
	}
	temporary := fmt.Sprintf("%s.tmp.%d.%d", absolute, os.Getpid(), time.Now().UnixNano())
	if err := validateDiagnosticPath(temporary, true); err != nil {
		return err
	}
	temporaryName, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(temporaryName, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.CREATE_NEW, windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("create diagnostic temporary file: %w", err)
	}
	writeErr := func() error {
		for len(data) > 0 {
			var written uint32
			if err := windows.WriteFile(handle, data, &written, nil); err != nil {
				return err
			}
			if written == 0 {
				return fmt.Errorf("diagnostic write made no progress")
			}
			data = data[written:]
		}
		return windows.FlushFileBuffers(handle)
	}()
	closeErr := windows.CloseHandle(handle)
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("write diagnostic temporary file: %w", errors.Join(writeErr, closeErr))
	}
	if err := secureDiagnosticPath(temporary); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := validateDiagnosticPath(absolute, override); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	destinationName, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := windows.MoveFileEx(temporaryName, destinationName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("atomically replace diagnostic: %w", err)
	}
	return secureDiagnosticPath(absolute)
}
