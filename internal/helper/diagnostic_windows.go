//go:build windows

package helper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
			return errors.New("diagnostic path contains a symlink")
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
			return errors.New("diagnostic path contains a reparse point")
		}
	}
	return nil
}

func diagnosticDACL() (*windows.ACL, error) {
	// Owner Rights keeps an explicitly requested diagnostic override testable by
	// its owner while the production ProgramData directory remains owned by the
	// service account. It does not grant access to unrelated users.
	securityDescriptor, err := windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;SU)(A;;FA;;;OW)")
	if err != nil {
		return nil, fmt.Errorf("build diagnostic ACL: %w", err)
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return nil, fmt.Errorf("read diagnostic ACL: %w", err)
	}
	return dacl, nil
}

func secureDiagnosticHandle(handle windows.Handle) error {
	dacl, err := diagnosticDACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply diagnostic ACL: %w", err)
	}
	return nil
}

func verifyDiagnosticHandle(handle windows.Handle, directory bool) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fmt.Errorf("inspect diagnostic handle: %w", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("diagnostic handle is a reparse point")
	}
	if directory && information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("diagnostic parent is not a directory")
	}
	return nil
}

func openVerifiedDiagnosticDirectory(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.WRITE_DAC,
		0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, fmt.Errorf("open diagnostic directory: %w", err)
	}
	if err := verifyDiagnosticHandle(handle, true); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	if err := secureDiagnosticHandle(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

type windowsDiagnosticFile struct {
	mu     sync.Mutex
	handle windows.Handle
}

func openDiagnosticFile(path string, override bool) (diagnosticFile, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve diagnostic path: %w", err)
	}
	if err := validateDiagnosticPath(absolute, override); err != nil {
		return nil, err
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create helper diagnostic directory: %w", err)
	}
	if err := validateDiagnosticPath(absolute, override); err != nil {
		return nil, err
	}
	directory, err := openVerifiedDiagnosticDirectory(parent)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(directory)
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, err
	}
	// No sharing keeps one fixed, non-reparse file handle for this helper
	// instance. All diagnostics are subsequently rewritten through this handle.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC,
		0, nil, windows.OPEN_ALWAYS,
		windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open fixed diagnostic file: %w", err)
	}
	if err := verifyDiagnosticHandle(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if err := secureDiagnosticHandle(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return &windowsDiagnosticFile{handle: handle}, nil
}

func (file *windowsDiagnosticFile) Write(data []byte) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.handle == windows.InvalidHandle {
		return errors.New("diagnostic file is closed")
	}
	if _, err := windows.SetFilePointer(file.handle, 0, nil, windows.FILE_BEGIN); err != nil {
		return fmt.Errorf("seek diagnostic file: %w", err)
	}
	if err := windows.SetEndOfFile(file.handle); err != nil {
		return fmt.Errorf("truncate diagnostic file: %w", err)
	}
	for len(data) > 0 {
		var written uint32
		if err := windows.WriteFile(file.handle, data, &written, nil); err != nil {
			return fmt.Errorf("write diagnostic file: %w", err)
		}
		if written == 0 {
			return errors.New("diagnostic write made no progress")
		}
		data = data[written:]
	}
	if err := windows.FlushFileBuffers(file.handle); err != nil {
		return fmt.Errorf("flush diagnostic file: %w", err)
	}
	return nil
}

func (file *windowsDiagnosticFile) Close() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(file.handle)
	file.handle = windows.InvalidHandle
	return err
}
