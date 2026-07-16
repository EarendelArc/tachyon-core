//go:build windows

package tun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	windowsRouteJournalVersion = 2
	windowsRouteJournalKey     = `SOFTWARE\Tachyon\RouteJournal`
	windowsRouteJournalValue   = "StateV2"

	windowsRoutePending  = "pending"
	windowsRouteActive   = "active"
	windowsRouteDeleting = "deleting"
)

var (
	windowsRouteJournalMu sync.Mutex
	advapi32              = windows.NewLazySystemDLL("advapi32.dll")
	procRegCreateKeyExW   = advapi32.NewProc("RegCreateKeyExW")
	procRegFlushKey       = advapi32.NewProc("RegFlushKey")
)

type windowsRouteJournalStorage interface {
	Read() ([]byte, error)
	Write([]byte) error
	Clear() error
	Location() string
}

type windowsRouteJournal struct {
	storage windowsRouteJournalStorage
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
	return &windowsRouteJournal{storage: &registryWindowsRouteJournalStorage{
		root:      registry.LOCAL_MACHINE,
		keyPath:   windowsRouteJournalKey,
		valueName: windowsRouteJournalValue,
	}}, nil
}

func newWindowsRouteJournalForTest() *windowsRouteJournal {
	return &windowsRouteJournal{storage: &memoryWindowsRouteJournalStorage{}}
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
		if entry.State == windowsRoutePending {
			// A pending create never established ownership.
			continue
		}
		if entry.State != windowsRouteActive && entry.State != windowsRouteDeleting {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("unsafe route journal state %q for %s", entry.State, prefix))
			continue
		}

		entry.State = windowsRouteDeleting
		staged := append(append([]windowsRouteJournalEntry(nil), kept...), entry)
		staged = append(staged, data.Entries[entryIdx+1:]...)
		if err := j.save(windowsRouteJournalData{Version: data.Version, Entries: staged}); err != nil {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("stage journaled route deletion %s: %w", prefix, err))
			continue
		}
		state, readErr := op.Read(ctx, prefix)
		if readErr != nil {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("read journaled route %s: %w", prefix, readErr))
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
		if readErr != nil || state.Matches {
			kept = append(kept, entry)
		}
		reconcileErr = errors.Join(reconcileErr, fmt.Errorf("delete journaled route %s: %w", prefix, errors.Join(deleteErr, readErr)))
	}
	data.Entries = kept
	return errors.Join(reconcileErr, j.save(data))
}

func (j *windowsRouteJournal) load() (windowsRouteJournalData, error) {
	data := windowsRouteJournalData{Version: windowsRouteJournalVersion}
	wire, err := j.storage.Read()
	if err != nil {
		return data, fmt.Errorf("read route journal %s: %w", j.storage.Location(), err)
	}
	if len(wire) == 0 {
		return data, nil
	}
	if err := json.Unmarshal(wire, &data); err != nil {
		return data, fmt.Errorf("parse route journal %s: %w", j.storage.Location(), err)
	}
	if data.Version != windowsRouteJournalVersion {
		return data, fmt.Errorf("unsupported route journal version %d", data.Version)
	}
	return data, nil
}

func (j *windowsRouteJournal) save(data windowsRouteJournalData) error {
	if len(data.Entries) == 0 {
		if err := j.storage.Clear(); err != nil {
			return fmt.Errorf("clear empty route journal %s: %w", j.storage.Location(), err)
		}
		return nil
	}
	wire, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := j.storage.Write(wire); err != nil {
		return fmt.Errorf("commit route journal %s: %w", j.storage.Location(), err)
	}
	return nil
}

type registryWindowsRouteJournalStorage struct {
	root      registry.Key
	keyPath   string
	valueName string
}

func (s *registryWindowsRouteJournalStorage) Location() string {
	return `HKLM\` + s.keyPath + `\` + s.valueName
}

func (s *registryWindowsRouteJournalStorage) Read() ([]byte, error) {
	key, err := registry.OpenKey(s.root, s.keyPath, registry.READ|registry.WOW64_64KEY)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer key.Close()
	if err := validateWindowsRouteJournalRegistryKey(key); err != nil {
		return nil, fmt.Errorf("untrusted route journal registry key: %w", err)
	}
	wire, valueType, err := key.GetBinaryValue(s.valueName)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if valueType != registry.BINARY {
		return nil, fmt.Errorf("registry value type is %d, want REG_BINARY", valueType)
	}
	return wire, nil
}

func (s *registryWindowsRouteJournalStorage) Write(wire []byte) error {
	key, _, err := createWindowsRouteJournalRegistryKey(s.root, s.keyPath)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := validateWindowsRouteJournalRegistryKey(key); err != nil {
		return fmt.Errorf("untrusted route journal registry key: %w", err)
	}
	if err := key.SetBinaryValue(s.valueName, wire); err != nil {
		return err
	}
	if err := flushWindowsRegistryKey(key); err != nil {
		return fmt.Errorf("flush route journal registry key: %w", err)
	}
	committed, valueType, err := key.GetBinaryValue(s.valueName)
	if err != nil {
		return fmt.Errorf("verify route journal registry value: %w", err)
	}
	if valueType != registry.BINARY || !bytes.Equal(committed, wire) {
		return errors.New("route journal registry value failed atomic readback verification")
	}
	return nil
}

func (s *registryWindowsRouteJournalStorage) Clear() error {
	key, err := registry.OpenKey(s.root, s.keyPath, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateWindowsRouteJournalRegistryKey(key); err != nil {
		key.Close()
		return fmt.Errorf("untrusted route journal registry key: %w", err)
	}
	if err := key.DeleteValue(s.valueName); err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		key.Close()
		return err
	}
	if err := key.Close(); err != nil {
		return err
	}
	if err := registry.DeleteKey(s.root, s.keyPath); err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return err
	}
	return nil
}

func createWindowsRouteJournalRegistryKey(root registry.Key, keyPath string) (registry.Key, bool, error) {
	descriptor, err := newWindowsRouteJournalSecurityDescriptor()
	if err != nil {
		return 0, false, err
	}
	path, err := windows.UTF16PtrFromString(keyPath)
	if err != nil {
		return 0, false, err
	}
	security := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: uintptr(unsafe.Pointer(descriptor)),
	}
	var handle syscall.Handle
	var disposition uint32
	status, _, _ := procRegCreateKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(path)),
		0,
		0,
		0,
		registry.ALL_ACCESS|registry.WOW64_64KEY,
		uintptr(unsafe.Pointer(&security)),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(security)
	if status != 0 {
		return 0, false, syscall.Errno(status)
	}
	return registry.Key(handle), disposition == 2, nil
}

func newWindowsRouteJournalSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)")
}

func flushWindowsRegistryKey(key registry.Key) error {
	status, _, _ := procRegFlushKey.Call(uintptr(key))
	if status != 0 {
		return syscall.Errno(status)
	}
	return nil
}

func validateWindowsRouteJournalRegistryKey(key registry.Key) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(key),
		windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	return validateWindowsJournalSecurityDescriptor(descriptor)
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
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != registry.ALL_ACCESS || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return fmt.Errorf("DACL ACE %d is not an explicit registry full-control allow entry", idx)
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

type memoryWindowsRouteJournalStorage struct {
	value      []byte
	writes     [][]byte
	clearCalls int
	readErr    error
	writeErr   error
	clearErr   error
}

func (s *memoryWindowsRouteJournalStorage) Location() string { return "test memory" }

func (s *memoryWindowsRouteJournalStorage) Read() ([]byte, error) {
	return append([]byte(nil), s.value...), s.readErr
}

func (s *memoryWindowsRouteJournalStorage) Write(wire []byte) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	committed := append([]byte(nil), wire...)
	s.value = committed
	s.writes = append(s.writes, committed)
	return nil
}

func (s *memoryWindowsRouteJournalStorage) Clear() error {
	if s.clearErr != nil {
		return s.clearErr
	}
	s.value = nil
	s.clearCalls++
	return nil
}
