//go:build windows

package tun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	windowsRouteJournalVersion     = 4
	windowsRouteJournalKey         = `SOFTWARE\Tachyon\RouteJournal`
	windowsRouteJournalValue       = "StateV4"
	windowsRouteCoordinationKey    = "CoordinationV4"
	windowsRouteJournalMutexPrefix = `Global\Tachyon.RouteJournal.v4.`
	windowsRouteJournalMaxSize     = 1 << 20
	windowsRouteLockTimeout        = 15 * time.Second

	windowsRoutePending  = "pending"
	windowsRouteActive   = "active"
	windowsRouteDeleting = "deleting"
)

var (
	advapi32            = windows.NewLazySystemDLL("advapi32.dll")
	procRegCreateKeyExW = advapi32.NewProc("RegCreateKeyExW")
	procRegFlushKey     = advapi32.NewProc("RegFlushKey")
)

type windowsRouteJournalStorage interface {
	Read() ([]byte, error)
	Write([]byte) error
	Location() string
}

type windowsRouteJournal struct {
	storage windowsRouteJournalStorage
	locker  windowsRouteJournalLocker
}

type windowsRouteJournalLocker interface {
	Lock() (*windowsRouteJournalLock, error)
}

type windowsRouteJournalLock struct {
	abandoned bool
	unlock    func() error
}

type windowsRouteJournalTransition struct {
	prefix netip.Prefix
	txnID  string
	lock   *windowsRouteJournalLock
}

type windowsRouteJournalData struct {
	Version int                        `json:"version"`
	Entries []windowsRouteJournalEntry `json:"entries"`
}

type windowsRouteJournalEntry struct {
	InterfaceLUID  uint64    `json:"interface_luid"`
	InterfaceIndex uint32    `json:"interface_index"`
	Destination    string    `json:"destination"`
	NextHop        string    `json:"next_hop"`
	Metric         uint32    `json:"metric"`
	Protocol       uint32    `json:"protocol"`
	TransactionID  string    `json:"transaction_id"`
	BaselineAbsent bool      `json:"baseline_absent"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
}

func newDefaultWindowsRouteJournal() (*windowsRouteJournal, error) {
	storage := &registryWindowsRouteJournalStorage{
		root:      registry.LOCAL_MACHINE,
		keyPath:   windowsRouteJournalKey,
		valueName: windowsRouteJournalValue,
	}
	return &windowsRouteJournal{storage: storage, locker: &protectedWindowsRouteJournalLocker{
		storage: storage,
		timeout: windowsRouteLockTimeout,
	}}, nil
}

func newWindowsRouteJournalForTest() *windowsRouteJournal {
	return &windowsRouteJournal{storage: &memoryWindowsRouteJournalStorage{}, locker: &localWindowsRouteJournalLocker{}}
}

func (j *windowsRouteJournal) prepare(ctx context.Context, op *windowsRouteOperator, prefix netip.Prefix) (retErr error) {
	if !op.adapterOwnershipProven() {
		return errors.New("Wintun adapter is not owned by the current process")
	}
	lock, err := j.locker.Lock()
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, lock.unlock())
		}
	}()
	if op.transition != nil {
		return errors.New("route journal transition is already in progress")
	}
	prefix = prefix.Masked()
	baseline, err := op.Read(ctx, prefix)
	if err != nil {
		return fmt.Errorf("verify route baseline while holding machine journal lock: %w", err)
	}
	if baseline.Exists {
		return fmt.Errorf("route baseline changed before journal prepare for %s", prefix)
	}
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.String()
	for _, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key {
			return fmt.Errorf("route journal already contains ownership for %s", key)
		}
	}
	txnID, err := newWindowsRouteTransactionID()
	if err != nil {
		return err
	}
	entry := newWindowsRouteJournalEntry(op, prefix, txnID, windowsRoutePending)
	data.Entries = append(data.Entries, entry)
	if err := j.save(data); err != nil {
		return err
	}
	op.transition = &windowsRouteJournalTransition{prefix: prefix, txnID: txnID, lock: lock}
	return nil
}

func (j *windowsRouteJournal) record(op *windowsRouteOperator, prefix netip.Prefix) error {
	return j.setState(op, prefix, windowsRouteActive)
}

func (j *windowsRouteJournal) prepareDeletion(ctx context.Context, op *windowsRouteOperator, prefix netip.Prefix) (retErr error) {
	if !op.adapterOwnershipProven() {
		return errors.New("Wintun adapter is not owned by the current process; refusing route deletion")
	}
	lock, err := j.locker.Lock()
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, lock.unlock())
		}
	}()
	if op.transition != nil {
		return errors.New("route journal transition is already in progress")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	prefix = prefix.Masked()
	data, err := j.load()
	if err != nil {
		return err
	}
	for idx, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == prefix.String() {
			if _, err := validateWindowsRouteJournalEntry(op, entry); err != nil {
				return fmt.Errorf("route journal ownership for %s has no verifiable signature: %w", prefix, err)
			}
			if entry.State != windowsRouteActive && entry.State != windowsRouteDeleting {
				return fmt.Errorf("route journal ownership for %s is in state %q", prefix, entry.State)
			}
			data.Entries[idx].State = windowsRouteDeleting
			if err := j.save(data); err != nil {
				return err
			}
			op.transition = &windowsRouteJournalTransition{prefix: prefix, txnID: entry.TransactionID, lock: lock}
			return nil
		}
	}
	return fmt.Errorf("route journal ownership is missing for %s", prefix)
}

func (j *windowsRouteJournal) setState(op *windowsRouteOperator, prefix netip.Prefix, state string) (retErr error) {
	transition, err := op.takeTransition(prefix)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, transition.lock.unlock()) }()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	for idx, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key && entry.TransactionID == transition.txnID {
			if _, err := validateWindowsRouteJournalEntry(op, entry); err != nil {
				return err
			}
			data.Entries[idx].State = state
			return j.save(data)
		}
	}
	return fmt.Errorf("route journal ownership is missing for %s", key)
}

func newWindowsRouteJournalEntry(op *windowsRouteOperator, prefix netip.Prefix, txnID, state string) windowsRouteJournalEntry {
	prefix = prefix.Masked()
	return windowsRouteJournalEntry{
		InterfaceLUID:  op.interfaceLUID,
		InterfaceIndex: op.interfaceIdx,
		Destination:    prefix.String(),
		NextHop:        windowsRouteNextHop(prefix),
		Metric:         windowsRouteMetric,
		Protocol:       windowsRouteProtocol,
		TransactionID:  txnID,
		BaselineAbsent: true,
		State:          state,
		CreatedAt:      time.Now().UTC(),
	}
}

func validateWindowsRouteJournalEntry(op *windowsRouteOperator, entry windowsRouteJournalEntry) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(entry.Destination)
	if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("invalid canonical destination %q", entry.Destination)
	}
	if entry.InterfaceLUID != op.interfaceLUID || entry.InterfaceIndex != op.interfaceIdx {
		return netip.Prefix{}, errors.New("adapter LUID/index does not match the current Wintun adapter")
	}
	if entry.NextHop != windowsRouteNextHop(prefix) || entry.Metric != windowsRouteMetric || entry.Protocol != windowsRouteProtocol {
		return netip.Prefix{}, errors.New("next-hop/protocol/metric does not match the fixed Tachyon route signature")
	}
	if !entry.BaselineAbsent {
		return netip.Prefix{}, errors.New("route baseline was not recorded absent")
	}
	txn, err := hex.DecodeString(entry.TransactionID)
	if err != nil || len(txn) != 16 {
		return netip.Prefix{}, errors.New("transaction ID is not a 128-bit hexadecimal value")
	}
	return prefix, nil
}

func windowsRouteNextHop(prefix netip.Prefix) string {
	if prefix.Addr().Is4() {
		return netip.IPv4Unspecified().String()
	}
	return netip.IPv6Unspecified().String()
}

func (j *windowsRouteJournal) release(op *windowsRouteOperator, prefix netip.Prefix) (retErr error) {
	transition, err := op.takeTransition(prefix)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, transition.lock.unlock())
	}()
	data, err := j.load()
	if err != nil {
		return err
	}
	key := prefix.Masked().String()
	kept := data.Entries[:0]
	for _, entry := range data.Entries {
		if entry.InterfaceLUID == op.interfaceLUID && entry.Destination == key && entry.TransactionID == transition.txnID {
			continue
		}
		kept = append(kept, entry)
	}
	data.Entries = kept
	return j.save(data)
}

func (j *windowsRouteJournal) reconcile(ctx context.Context, op *windowsRouteOperator) (retErr error) {
	if !op.adapterOwnershipProven() {
		return errors.New("Wintun adapter is not owned by the current process; refusing route recovery")
	}
	lock, err := j.locker.Lock()
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, lock.unlock()) }()
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
		prefix, signatureErr := validateWindowsRouteJournalEntry(op, entry)
		if signatureErr != nil {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("unsafe route journal entry for Wintun LUID %d destination %q: %w", entry.InterfaceLUID, entry.Destination, signatureErr))
			continue
		}
		if entry.State != windowsRouteActive && entry.State != windowsRouteDeleting {
			if entry.State != windowsRoutePending {
				kept = append(kept, entry)
				reconcileErr = errors.Join(reconcileErr, fmt.Errorf("unsafe route journal state %q for %s", entry.State, prefix))
				continue
			}
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
		if entry.State == windowsRoutePending {
			entry.State = windowsRouteActive
			staged := append(append([]windowsRouteJournalEntry(nil), kept...), entry)
			staged = append(staged, data.Entries[entryIdx+1:]...)
			if err := j.save(windowsRouteJournalData{Version: data.Version, Entries: staged}); err != nil {
				kept = append(kept, entry)
				reconcileErr = errors.Join(reconcileErr, fmt.Errorf("claim pending journaled route %s: %w", prefix, err))
				continue
			}
		}

		entry.State = windowsRouteDeleting
		staged := append(append([]windowsRouteJournalEntry(nil), kept...), entry)
		staged = append(staged, data.Entries[entryIdx+1:]...)
		if err := j.save(windowsRouteJournalData{Version: data.Version, Entries: staged}); err != nil {
			kept = append(kept, entry)
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("stage journaled route deletion %s: %w", prefix, err))
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

func (o *windowsRouteOperator) takeTransition(prefix netip.Prefix) (*windowsRouteJournalTransition, error) {
	prefix = prefix.Masked()
	transition := o.transition
	if transition == nil || transition.prefix != prefix {
		return nil, fmt.Errorf("no machine-locked route journal transition for %s", prefix)
	}
	o.transition = nil
	return transition, nil
}

func newWindowsRouteTransactionID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate route transaction ID: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}

type namedWindowsRouteJournalLocker struct {
	name    string
	timeout time.Duration
}

type protectedWindowsRouteJournalLocker struct {
	storage *registryWindowsRouteJournalStorage
	timeout time.Duration
}

type localWindowsRouteJournalLocker struct {
	mu sync.Mutex
}

func (l *localWindowsRouteJournalLocker) Lock() (*windowsRouteJournalLock, error) {
	l.mu.Lock()
	return &windowsRouteJournalLock{unlock: func() error {
		l.mu.Unlock()
		return nil
	}}, nil
}

func (l *protectedWindowsRouteJournalLocker) Lock() (*windowsRouteJournalLock, error) {
	name, err := l.storage.machineMutexName()
	if err != nil {
		return nil, fmt.Errorf("derive protected machine route journal mutex: %w", err)
	}
	return (&namedWindowsRouteJournalLocker{name: name, timeout: l.timeout}).Lock()
}

func (l *namedWindowsRouteJournalLocker) Lock() (_ *windowsRouteJournalLock, retErr error) {
	descriptor, err := newWindowsRouteMutexSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return nil, err
	}
	security := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	runtime.LockOSThread()
	defer func() {
		if retErr != nil {
			runtime.UnlockOSThread()
		}
	}()
	handle, err := windows.CreateMutex(&security, false, name)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(security)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, fmt.Errorf("create machine route journal mutex %q: %w", l.name, err)
	}
	if handle == 0 {
		return nil, fmt.Errorf("create machine route journal mutex %q returned an invalid handle", l.name)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			windows.CloseHandle(handle)
		}
	}()
	if err := validateWindowsRouteMutex(handle); err != nil {
		return nil, fmt.Errorf("untrusted machine route journal mutex %q: %w", l.name, err)
	}
	timeout := l.timeout
	if timeout <= 0 {
		timeout = windowsRouteLockTimeout
	}
	wait, err := windows.WaitForSingleObject(handle, uint32(timeout/time.Millisecond))
	if err != nil {
		return nil, fmt.Errorf("wait for machine route journal mutex %q: %w", l.name, err)
	}
	if wait != windows.WAIT_OBJECT_0 && wait != windows.WAIT_ABANDONED {
		if wait == uint32(windows.WAIT_TIMEOUT) {
			return nil, fmt.Errorf("timed out after %s waiting for machine route journal mutex %q", timeout, l.name)
		}
		return nil, fmt.Errorf("unexpected wait result %d for machine route journal mutex %q", wait, l.name)
	}
	// WAIT_ABANDONED transfers ownership to this thread. Every caller reloads
	// and validates the durable journal before making its next mutation.
	closeOnError = false
	return &windowsRouteJournalLock{
		abandoned: wait == windows.WAIT_ABANDONED,
		unlock: func() error {
			releaseErr := windows.ReleaseMutex(handle)
			closeErr := windows.CloseHandle(handle)
			runtime.UnlockOSThread()
			return errors.Join(releaseErr, closeErr)
		},
	}, nil
}

func newWindowsRouteMutexSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;;0x001F0001;;;SY)(A;;0x001F0001;;;BA)")
}

func validateWindowsRouteMutex(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	return validateWindowsTrustedACL(descriptor, windows.MUTEX_ALL_ACCESS, "mutex")
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
	seenTransactions := make(map[string]struct{}, len(data.Entries))
	for _, entry := range data.Entries {
		if _, exists := seenTransactions[entry.TransactionID]; exists {
			return data, fmt.Errorf("duplicate route journal transaction ID %q", entry.TransactionID)
		}
		seenTransactions[entry.TransactionID] = struct{}{}
	}
	return data, nil
}

func (j *windowsRouteJournal) save(data windowsRouteJournalData) error {
	wire, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if len(wire) > windowsRouteJournalMaxSize {
		return fmt.Errorf("route journal is %d bytes; maximum is %d", len(wire), windowsRouteJournalMaxSize)
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
	return queryBoundedWindowsRegistryBinaryValue(key, s.valueName)
}

func (s *registryWindowsRouteJournalStorage) Write(wire []byte) error {
	if len(wire) > windowsRouteJournalMaxSize {
		return fmt.Errorf("registry value is %d bytes; maximum is %d", len(wire), windowsRouteJournalMaxSize)
	}
	key, _, err := createWindowsRouteJournalRegistryKey(s.root, s.keyPath, "")
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
	committed, err := queryBoundedWindowsRegistryBinaryValue(key, s.valueName)
	if err != nil {
		return fmt.Errorf("verify route journal registry value: %w", err)
	}
	if !bytes.Equal(committed, wire) {
		return errors.New("route journal registry value failed atomic readback verification")
	}
	return nil
}

func (s *registryWindowsRouteJournalStorage) machineMutexName() (string, error) {
	base, _, err := createWindowsRouteJournalRegistryKey(s.root, s.keyPath, "")
	if err != nil {
		return "", err
	}
	if err := validateWindowsRouteJournalRegistryKey(base); err != nil {
		base.Close()
		return "", fmt.Errorf("untrusted route journal registry key: %w", err)
	}
	if err := base.Close(); err != nil {
		return "", err
	}

	secret, err := newWindowsRouteTransactionID()
	if err != nil {
		return "", err
	}
	coordinationPath := s.keyPath + `\` + windowsRouteCoordinationKey
	coordination, _, err := createWindowsRouteJournalRegistryKey(s.root, coordinationPath, secret)
	if err != nil {
		return "", err
	}
	defer coordination.Close()
	if err := validateWindowsRouteJournalRegistryKey(coordination); err != nil {
		return "", fmt.Errorf("untrusted route journal coordination key: %w", err)
	}
	secret, err = queryWindowsRegistryKeyClass(coordination)
	if err != nil {
		return "", err
	}
	decoded, err := hex.DecodeString(secret)
	if err != nil || len(decoded) != 16 {
		return "", errors.New("route journal coordination secret is not a 128-bit hexadecimal value")
	}
	return windowsRouteJournalMutexPrefix + secret, nil
}

func queryBoundedWindowsRegistryBinaryValue(key registry.Key, valueName string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(valueName)
	if err != nil {
		return nil, err
	}
	return readBoundedWindowsRegistryBinaryValue(func(valueType *uint32, data *byte, size *uint32) error {
		return windows.RegQueryValueEx(windows.Handle(key), name, nil, valueType, data, size)
	})
}

type windowsRegistryValueQuery func(valueType *uint32, data *byte, size *uint32) error

func readBoundedWindowsRegistryBinaryValue(query windowsRegistryValueQuery) ([]byte, error) {
	var valueType uint32
	var size uint32
	err := query(&valueType, nil, &size)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if valueType != registry.BINARY {
		return nil, fmt.Errorf("registry value type is %d, want REG_BINARY", valueType)
	}
	if size > windowsRouteJournalMaxSize {
		return nil, fmt.Errorf("registry value is %d bytes; maximum is %d", size, windowsRouteJournalMaxSize)
	}
	if size == 0 {
		return []byte{}, nil
	}
	wire := make([]byte, size)
	actual := size
	if err := query(&valueType, &wire[0], &actual); err != nil {
		return nil, fmt.Errorf("read registry value after bounded size query: %w", err)
	}
	if valueType != registry.BINARY || actual != size {
		return nil, errors.New("registry value type or size changed during read")
	}
	return wire, nil
}

func createWindowsRouteJournalRegistryKey(root registry.Key, keyPath, class string) (registry.Key, bool, error) {
	descriptor, err := newWindowsRouteJournalSecurityDescriptor()
	if err != nil {
		return 0, false, err
	}
	path, err := windows.UTF16PtrFromString(keyPath)
	if err != nil {
		return 0, false, err
	}
	var classPtr *uint16
	if class != "" {
		classPtr, err = windows.UTF16PtrFromString(class)
		if err != nil {
			return 0, false, err
		}
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
		uintptr(unsafe.Pointer(classPtr)),
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
	return validateWindowsTrustedACL(descriptor, registry.ALL_ACCESS, "registry")
}

func validateWindowsTrustedACL(descriptor *windows.SECURITY_DESCRIPTOR, requiredMask windows.ACCESS_MASK, objectKind string) error {
	if descriptor == nil || !descriptor.IsValid() {
		return errors.New("missing or invalid security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("owner %v is not Administrators", owner)
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
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != requiredMask || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return fmt.Errorf("DACL ACE %d is not an explicit %s full-control allow entry", idx, objectKind)
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

func queryWindowsRegistryKeyClass(key registry.Key) (string, error) {
	buffer := make([]uint16, 64)
	length := uint32(len(buffer))
	if err := windows.RegQueryInfoKey(windows.Handle(key), &buffer[0], &length, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		return "", fmt.Errorf("read route journal coordination secret: %w", err)
	}
	if length == 0 || length >= uint32(len(buffer)) {
		return "", errors.New("route journal coordination key has an invalid class secret")
	}
	return windows.UTF16ToString(buffer[:length]), nil
}

func aclEntryCount(acl *windows.ACL) uint16 {
	if acl == nil {
		return 0
	}
	return acl.AceCount
}

type memoryWindowsRouteJournalStorage struct {
	value    []byte
	writes   [][]byte
	readErr  error
	writeErr error
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
