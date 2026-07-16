//go:build windows

package tun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsRouteJournalVersion = 2

const (
	windowsRoutePending  = "pending"
	windowsRouteActive   = "active"
	windowsRouteDeleting = "deleting"
)

var windowsRouteJournalMu sync.Mutex

type windowsRouteJournalSecurity interface {
	Prepare(root, path string) error
	Protect(path string) error
	Validate(path string) error
}

type windowsRouteJournal struct {
	root     string
	path     string
	security windowsRouteJournalSecurity
}

type windowsRouteJournalData struct {
	Version int                        `json:"version"`
	Entries []windowsRouteJournalEntry `json:"entries"`
}

type windowsRouteJournalEntry struct {
	InterfaceLUID  uint64    `json:"interface_luid"`
	InterfaceIndex uint32    `json:"interface_index"`
	Destination    string    `json:"destination"`
	Metric         uint32    `json:"metric"`
	Protocol       uint32    `json:"protocol"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
}

func newDefaultWindowsRouteJournal() (*windowsRouteJournal, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, fmt.Errorf("resolve Windows ProgramData for route journal: %w", err)
	}
	root := filepath.Join(programData, "Tachyon")
	return &windowsRouteJournal{
		root:     root,
		path:     filepath.Join(root, "route-journal-v2.json"),
		security: systemWindowsRouteJournalSecurity{},
	}, nil
}

func newWindowsRouteJournalForTest(path string) *windowsRouteJournal {
	return &windowsRouteJournal{
		root:     filepath.Dir(path),
		path:     path,
		security: testWindowsRouteJournalSecurity{},
	}
}

func (j *windowsRouteJournal) prepare(op *windowsRouteOperator, prefix netip.Prefix) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	for idx, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key {
			data.Entries[idx] = newWindowsRouteJournalEntry(op, key, windowsRoutePending)
			return j.save(data)
		}
	}
	data.Entries = append(data.Entries, newWindowsRouteJournalEntry(op, key, windowsRoutePending))
	return j.save(data)
}

func (j *windowsRouteJournal) record(op *windowsRouteOperator, prefix netip.Prefix) error {
	return j.setState(op, prefix, windowsRouteActive)
}

func (j *windowsRouteJournal) prepareDeletion(op *windowsRouteOperator, prefix netip.Prefix) error {
	return j.setState(op, prefix, windowsRouteDeleting)
}

func (j *windowsRouteJournal) setState(op *windowsRouteOperator, prefix netip.Prefix, state string) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	for idx, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key {
			data.Entries[idx].State = state
			return j.save(data)
		}
	}
	return fmt.Errorf("route journal ownership is missing for %s", key)
}

func newWindowsRouteJournalEntry(op *windowsRouteOperator, key, state string) windowsRouteJournalEntry {
	return windowsRouteJournalEntry{
		InterfaceLUID:  op.interfaceLUID,
		InterfaceIndex: op.interfaceIdx,
		Destination:    key,
		Metric:         windowsRouteMetric,
		Protocol:       windowsRouteProtocol,
		State:          state,
		CreatedAt:      time.Now().UTC(),
	}
}

func (j *windowsRouteJournal) release(op *windowsRouteOperator, prefix netip.Prefix) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	kept := data.Entries[:0]
	for _, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key {
			continue
		}
		kept = append(kept, entry)
	}
	data.Entries = kept
	return j.save(data)
}

func (j *windowsRouteJournal) reconcile(ctx context.Context, op *windowsRouteOperator) error {
	windowsRouteJournalMu.Lock()
	defer windowsRouteJournalMu.Unlock()
	data, err := j.load()
	if err != nil {
		return err
	}
	kept := make([]windowsRouteJournalEntry, 0, len(data.Entries))
	var reconcileErr error
	for entryIdx, entry := range data.Entries {
		if entry.InterfaceLUID != op.interfaceLUID {
			kept = append(kept, entry)
			continue
		}
		prefix, parseErr := netip.ParsePrefix(entry.Destination)
		if parseErr != nil || entry.InterfaceIndex != op.interfaceIdx || entry.Metric != windowsRouteMetric || entry.Protocol != windowsRouteProtocol {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("unsafe route journal entry for Wintun LUID %d destination %q", entry.InterfaceLUID, entry.Destination))
			continue
		}
		if entry.State != windowsRouteActive {
			// Pending and deleting entries are deliberately non-authoritative.
			// A crash can leak a route, but it cannot turn ambiguity into deletion.
			continue
		}
		entry.State = windowsRouteDeleting
		staged := append(append([]windowsRouteJournalEntry(nil), kept...), entry)
		staged = append(staged, data.Entries[entryIdx+1:]...)
		if err := j.save(windowsRouteJournalData{Version: data.Version, Entries: staged}); err != nil {
			entry.State = windowsRouteActive
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("stage journaled route deletion %s: %w", prefix, err))
			continue
		}
		state, readErr := op.Read(ctx, prefix)
		if readErr != nil {
			entry.State = windowsRouteActive
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, readErr)
			continue
		}
		if !state.Matches {
			continue
		}
		deleteResult, deleteErr := op.Delete(ctx, prefix)
		if deleteResult.Committed || deleteErr == nil {
			continue
		}
		state, readErr = op.Read(ctx, prefix)
		if readErr == nil && state.Matches {
			entry.State = windowsRouteActive
			kept = append(kept, entry)
		}
		reconcileErr = errors.Join(reconcileErr, fmt.Errorf("delete journaled route %s: %w", prefix, errors.Join(deleteErr, readErr)))
	}
	data.Entries = kept
	return errors.Join(reconcileErr, j.save(data))
}

func (j *windowsRouteJournal) load() (windowsRouteJournalData, error) {
	data := windowsRouteJournalData{Version: windowsRouteJournalVersion}
	if err := j.security.Prepare(j.root, j.path); err != nil {
		return data, err
	}
	wire, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return data, nil
	}
	if err != nil {
		return data, fmt.Errorf("read route journal %q: %w", j.path, err)
	}
	if err := json.Unmarshal(wire, &data); err != nil {
		return data, fmt.Errorf("parse route journal %q: %w", j.path, err)
	}
	if data.Version != windowsRouteJournalVersion {
		return data, fmt.Errorf("unsupported route journal version %d", data.Version)
	}
	return data, nil
}

func (j *windowsRouteJournal) save(data windowsRouteJournalData) error {
	if err := j.security.Prepare(j.root, j.path); err != nil {
		return err
	}
	if len(data.Entries) == 0 {
		if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty route journal %q: %w", j.path, err)
		}
		return nil
	}
	wire, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(j.root, ".route-journal-*.tmp")
	if err != nil {
		return fmt.Errorf("create route journal temporary file: %w", err)
	}
	tmp := tmpFile.Name()
	committed := false
	defer func() {
		_ = tmpFile.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if err := j.security.Protect(tmp); err != nil {
		return fmt.Errorf("protect route journal temporary file: %w", err)
	}
	if _, err := tmpFile.Write(wire); err != nil {
		return fmt.Errorf("write route journal: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("flush route journal: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close route journal: %w", err)
	}
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(j.path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("commit route journal: %w", err)
	}
	committed = true
	if err := j.security.Protect(j.path); err != nil {
		return fmt.Errorf("reprotect committed route journal: %w", err)
	}
	if err := j.security.Validate(j.path); err != nil {
		return fmt.Errorf("verify committed route journal: %w", err)
	}
	return nil
}

type systemWindowsRouteJournalSecurity struct{}

func (systemWindowsRouteJournalSecurity) Prepare(root, path string) error {
	if err := validateWindowsJournalPath(root, path); err != nil {
		return err
	}
	if err := rejectWindowsReparseComponents(filepath.Dir(root)); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return fmt.Errorf("create protected route journal directory: %w", err)
		}
		if err := protectWindowsJournalObject(root); err != nil {
			return fmt.Errorf("protect route journal directory: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect route journal directory: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("route journal root %q is not a directory", root)
	}
	if err := rejectWindowsReparseComponents(root); err != nil {
		return err
	}
	if err := validateWindowsJournalObject(root); err != nil {
		return fmt.Errorf("untrusted route journal directory: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateWindowsJournalObject(path); err != nil {
			return fmt.Errorf("untrusted route journal file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect route journal file: %w", err)
	}
	return nil
}

func (systemWindowsRouteJournalSecurity) Protect(path string) error {
	return protectWindowsJournalObject(path)
}

func (systemWindowsRouteJournalSecurity) Validate(path string) error {
	return validateWindowsJournalObject(path)
}

// Tests use temporary user-owned directories and exercise security descriptor
// validation separately, so their journal I/O does not lock out the test user.
type testWindowsRouteJournalSecurity struct{}

func (testWindowsRouteJournalSecurity) Prepare(root, path string) error {
	if err := validateWindowsJournalPath(root, path); err != nil {
		return err
	}
	return os.MkdirAll(root, 0o700)
}
func (testWindowsRouteJournalSecurity) Protect(string) error  { return nil }
func (testWindowsRouteJournalSecurity) Validate(string) error { return nil }

func validateWindowsJournalPath(root, path string) error {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return fmt.Errorf("resolve route journal root: %w", err)
	}
	pathAbs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve route journal path: %w", err)
	}
	if !strings.EqualFold(filepath.Dir(pathAbs), rootAbs) {
		return fmt.Errorf("route journal path %q escapes protected root %q", pathAbs, rootAbs)
	}
	return nil
}

func rejectWindowsReparseComponents(path string) error {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	current := volume + string(os.PathSeparator)
	rest := strings.TrimPrefix(path, current)
	for _, component := range strings.Split(rest, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect route journal path component %q: %w", current, err)
		}
		if err := validateWindowsJournalAttributes(current, attrs); err != nil {
			return err
		}
	}
	return nil
}

func protectWindowsJournalObject(path string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return err
	}
	if err := validateWindowsJournalAttributes(path, attrs); err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsJournalAccessEntry(systemSID, windows.TRUSTEE_IS_USER, inheritance),
		windowsJournalAccessEntry(adminSID, windows.TRUSTEE_IS_GROUP, inheritance),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		adminSID,
		nil,
		dacl,
		nil,
	); err != nil {
		return err
	}
	return validateWindowsJournalObject(path)
}

func windowsJournalAccessEntry(sid *windows.SID, trusteeType windows.TRUSTEE_TYPE, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func validateWindowsJournalObject(path string) error {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return err
	}
	if err := validateWindowsJournalAttributes(path, attrs); err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	return validateWindowsJournalSecurityDescriptor(descriptor)
}

func validateWindowsJournalAttributes(path string, attrs uint32) error {
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("route journal path %q is a reparse point", path)
	}
	return nil
}

func validateWindowsJournalSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil || !descriptor.IsValid() {
		return errors.New("missing or invalid security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || (!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return fmt.Errorf("owner %v is not SYSTEM or Administrators", owner)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("DACL inheritance is enabled")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount != 2 {
		return fmt.Errorf("DACL has %d ACEs; expected exactly SYSTEM and Administrators", aclEntryCount(dacl))
	}
	seenSystem := false
	seenAdmins := false
	for idx := uint16(0); idx < dacl.AceCount; idx++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(idx), &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != windows.GENERIC_ALL || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return fmt.Errorf("DACL ACE %d is not an explicit full-control allow entry", idx)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			seenSystem = true
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			seenAdmins = true
		default:
			return fmt.Errorf("DACL ACE %d grants an untrusted SID %s", idx, sid.String())
		}
	}
	if !seenSystem || !seenAdmins {
		return errors.New("DACL does not grant both SYSTEM and Administrators")
	}
	return nil
}

func aclEntryCount(acl *windows.ACL) uint16 {
	if acl == nil {
		return 0
	}
	return acl.AceCount
}
