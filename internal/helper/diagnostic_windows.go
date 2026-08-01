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
	if strings.EqualFold(filepath.Clean(absolute), filepath.Clean(defaultDiagnosticPath())) {
		return rejectDiagnosticReparsePoints(absolute)
	}
	if !override || !isHarnessDiagnosticPath(absolute) {
		return fmt.Errorf("diagnostic path must be the protected ProgramData path or a managed harness path")
	}
	return rejectDiagnosticReparsePoints(absolute)
}

func isHarnessDiagnosticPath(path string) bool {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	root := filepath.Join(programData, "Tachyon", "Harness")
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") || filepath.IsAbs(relative) {
		return false
	}
	parts := strings.FieldsFunc(relative, func(r rune) bool { return r == '\\' || r == '/' })
	return len(parts) == 2 && isHarnessGUID(parts[0]) && strings.EqualFold(parts[1], "helper-health.json")
}

func isHarnessGUID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
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

const (
	diagnosticDirectoryAccess windows.ACCESS_MASK = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	diagnosticFileAccess      windows.ACCESS_MASK = diagnosticDirectoryAccess | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
)

// diagnosticSecurityError is intentionally mapped to ERROR_ACCESS_DENIED by
// the SCM host. That gives operators a non-secret Event Log/SCM signal that
// provisioning is missing or has been tampered with.
type diagnosticSecurityError struct{ err error }

func (err *diagnosticSecurityError) Error() string { return err.err.Error() }
func (err *diagnosticSecurityError) Unwrap() error { return err.err }

func newDiagnosticSecurityError(format string, arguments ...any) error {
	return &diagnosticSecurityError{err: fmt.Errorf(format, arguments...)}
}

func expectedDiagnosticSecurity(serviceSID, ownerSID string, file bool) (*windows.SECURITY_DESCRIPTOR, error) {
	if _, err := windows.StringToSid(serviceSID); err != nil {
		return nil, newDiagnosticSecurityError("invalid diagnostic service SID: %v", err)
	}
	if _, err := windows.StringToSid(ownerSID); err != nil {
		return nil, newDiagnosticSecurityError("invalid diagnostic owner SID: %v", err)
	}
	rights := diagnosticDirectoryAccess
	if file {
		rights = diagnosticFileAccess
	}
	// The installer owns the pre-provisioned artifact. The service receives the
	// canonical owner SID as configuration and only verifies it; it never needs
	// SeTakeOwnershipPrivilege or WRITE_OWNER.
	sddl := fmt.Sprintf("O:%sD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x%X;;;LS)(A;;0x%X;;;%s)", ownerSID, uint32(rights), uint32(rights), serviceSID)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, newDiagnosticSecurityError("build expected diagnostic ACL: %v", err)
	}
	return descriptor, nil
}

func verifyDiagnosticHandle(handle windows.Handle, directory bool, serviceSID, ownerSID string) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return newDiagnosticSecurityError("inspect diagnostic handle: %v", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return newDiagnosticSecurityError("diagnostic handle is a reparse point")
	}
	if directory && information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return newDiagnosticSecurityError("diagnostic parent is not a directory")
	}
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return newDiagnosticSecurityError("read diagnostic security descriptor: %v", err)
	}
	expected, err := expectedDiagnosticSecurity(serviceSID, ownerSID, !directory)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual.String(), expected.String()) {
		return newDiagnosticSecurityError("diagnostic ACL or owner does not match pre-provisioned policy")
	}
	return nil
}

func openVerifiedDiagnosticDirectory(path, serviceSID, ownerSID string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, uint32(diagnosticDirectoryAccess),
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, newDiagnosticSecurityError("open pre-provisioned diagnostic directory: %v", err)
	}
	if err := verifyDiagnosticHandle(handle, true, serviceSID, ownerSID); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

type windowsDiagnosticFile struct {
	mu     sync.Mutex
	handle windows.Handle
}

func openDiagnosticFile(path string, override bool, serviceSID, ownerSID string) (diagnosticFile, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve diagnostic path: %w", err)
	}
	if err := validateDiagnosticPath(absolute, override); err != nil {
		return nil, newDiagnosticSecurityError("validate diagnostic path: %v", err)
	}
	parent := filepath.Dir(absolute)
	directory, err := openVerifiedDiagnosticDirectory(parent, serviceSID, ownerSID)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(directory)
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, err
	}
	// Read sharing permits an administrator-owned harness to inspect health while
	// the service is running. Write/delete sharing remains denied, leaving one
	// fixed, non-reparse writer handle for this helper instance.
	handle, err := windows.CreateFile(name, uint32(diagnosticFileAccess),
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, newDiagnosticSecurityError("open pre-provisioned diagnostic file: %v", err)
	}
	if err := verifyDiagnosticHandle(handle, false, serviceSID, ownerSID); err != nil {
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
