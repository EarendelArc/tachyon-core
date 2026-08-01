//go:build windows

package capturedudp

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

const (
	namedPipeServerProcessQueryAccess windows.ACCESS_MASK = windows.PROCESS_QUERY_LIMITED_INFORMATION
	namedPipeServerTokenQueryAccess   windows.ACCESS_MASK = windows.TOKEN_QUERY
)

// grantNamedPipeClientIdentityQueryAccess lets an explicitly allowlisted
// helper verify the Core process and token. It adds query-only access to the
// existing DACLs; pipe ACL, SID, integrity, image, hash, PID, and creation-time
// verification remain independent and fail closed.
func grantNamedPipeClientIdentityQueryAccess(allowedSIDs []string) error {
	process, err := windows.OpenProcess(windows.READ_CONTROL|windows.WRITE_DAC, false, uint32(os.Getpid()))
	if err != nil {
		return fmt.Errorf("open Core process security for helper identity verification: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := grantKernelObjectAccess(process, allowedSIDs, namedPipeServerProcessQueryAccess); err != nil {
		return fmt.Errorf("grant helper Core process query access: %w", err)
	}

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.READ_CONTROL|windows.WRITE_DAC, &token); err != nil {
		return fmt.Errorf("open Core token security for helper identity verification: %w", err)
	}
	defer token.Close()
	if err := grantKernelObjectAccess(windows.Handle(token), allowedSIDs, namedPipeServerTokenQueryAccess); err != nil {
		return fmt.Errorf("grant helper Core token query access: %w", err)
	}
	return nil
}

func grantKernelObjectAccess(handle windows.Handle, sidTexts []string, access windows.ACCESS_MASK) error {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read kernel object DACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read protected kernel object DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("%w: kernel object has an empty DACL", ErrNamedPipeIdentity)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sidTexts))
	sids := make([]*windows.SID, 0, len(sidTexts))
	for _, sidText := range sidTexts {
		sid, parseErr := windows.StringToSid(sidText)
		if parseErr != nil {
			return fmt.Errorf("parse helper SID %q: %w", sidText, parseErr)
		}
		sids = append(sids, sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: access,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	updated, err := windows.ACLFromEntries(entries, dacl)
	runtime.KeepAlive(sids)
	if err != nil {
		return fmt.Errorf("merge query-only kernel object ACEs: %w", err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, updated, nil); err != nil {
		return fmt.Errorf("persist query-only kernel object ACEs: %w", err)
	}
	return nil
}
