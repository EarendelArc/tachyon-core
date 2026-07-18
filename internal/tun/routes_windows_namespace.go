//go:build windows

package tun

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsRouteNamespaceAlias       = "TachyonRouteJournal"
	windowsRouteBoundaryName         = "Tachyon.RouteJournal.Administrators.v1"
	windowsRouteNamespaceMutexName   = "MachineLock"
	windowsPrivateNamespaceDestroy   = 0x1
	windowsPrivateNamespaceOpenTries = 3
)

var (
	namespaceAPI                   = windows.NewLazySystemDLL("kernel32.dll")
	procCreateBoundaryDescriptorW  = namespaceAPI.NewProc("CreateBoundaryDescriptorW")
	procAddSIDToBoundaryDescriptor = namespaceAPI.NewProc("AddSIDToBoundaryDescriptor")
	procDeleteBoundaryDescriptor   = namespaceAPI.NewProc("DeleteBoundaryDescriptor")
	procCreatePrivateNamespaceW    = namespaceAPI.NewProc("CreatePrivateNamespaceW")
	procOpenPrivateNamespaceW      = namespaceAPI.NewProc("OpenPrivateNamespaceW")
	procClosePrivateNamespace      = namespaceAPI.NewProc("ClosePrivateNamespace")
	windowsRoutePrivateNamespaces  = newWindowsPrivateNamespaceRegistry(
		openWindowsPrivateNamespace,
		func(namespace *windowsPrivateNamespace) error { return namespace.Close(false) },
	)
)

type windowsPrivateNamespace struct {
	handle   windows.Handle
	boundary windows.Handle
}

type windowsPrivateNamespaceIdentity struct {
	alias        string
	boundaryName string
	boundarySID  string
	descriptor   string
}

type windowsPrivateNamespaceEntry struct {
	identity   windowsPrivateNamespaceIdentity
	namespace  *windowsPrivateNamespace
	references int
	closeErr   error
}

type windowsPrivateNamespaceRegistry struct {
	mu      sync.Mutex
	entries map[string]*windowsPrivateNamespaceEntry
	open    func(string, string, *windows.SID, *windows.SECURITY_DESCRIPTOR) (*windowsPrivateNamespace, error)
	close   func(*windowsPrivateNamespace) error
}

type windowsPrivateNamespaceReference struct {
	registry *windowsPrivateNamespaceRegistry
	entry    *windowsPrivateNamespaceEntry
	once     sync.Once
	closeErr error
}

type privateWindowsRouteJournalLocker struct {
	alias        string
	boundaryName string
	mutexName    string
	timeout      time.Duration

	mu        sync.Mutex
	registry  *windowsPrivateNamespaceRegistry
	namespace *windowsPrivateNamespaceReference
	newMutex  func(string, time.Duration) *namedWindowsRouteJournalLocker
	mutex     *namedWindowsRouteJournalLocker
	closed    bool
}

func newWindowsPrivateNamespaceRegistry(
	open func(string, string, *windows.SID, *windows.SECURITY_DESCRIPTOR) (*windowsPrivateNamespace, error),
	close func(*windowsPrivateNamespace) error,
) *windowsPrivateNamespaceRegistry {
	return &windowsPrivateNamespaceRegistry{
		entries: make(map[string]*windowsPrivateNamespaceEntry),
		open:    open,
		close:   close,
	}
}

func newPrivateWindowsRouteJournalLocker(alias, boundaryName, mutexName string, timeout time.Duration) *privateWindowsRouteJournalLocker {
	return &privateWindowsRouteJournalLocker{
		alias:        alias,
		boundaryName: boundaryName,
		mutexName:    mutexName,
		timeout:      timeout,
		registry:     windowsRoutePrivateNamespaces,
		newMutex: func(name string, timeout time.Duration) *namedWindowsRouteJournalLocker {
			return &namedWindowsRouteJournalLocker{name: name, timeout: timeout}
		},
	}
}

func (l *privateWindowsRouteJournalLocker) Open() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.openLocked()
}

func (l *privateWindowsRouteJournalLocker) Lock() (*windowsRouteJournalLock, error) {
	l.mu.Lock()
	if err := l.openLocked(); err != nil {
		l.mu.Unlock()
		return nil, err
	}
	mutex := l.mutex
	l.mu.Unlock()
	return mutex.Lock()
}

func (l *privateWindowsRouteJournalLocker) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var closeErr error
	if l.mutex != nil {
		closeErr = l.mutex.Close()
		l.mutex = nil
	}
	if l.namespace != nil {
		closeErr = errors.Join(closeErr, l.namespace.Close())
		l.namespace = nil
	}
	return closeErr
}

func (l *privateWindowsRouteJournalLocker) openLocked() error {
	if l.closed {
		return errors.New("private machine route journal locker is closed")
	}
	if l.mutex != nil {
		return nil
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID for route journal namespace: %w", err)
	}
	descriptor, err := newWindowsRouteNamespaceSecurityDescriptor()
	if err != nil {
		return err
	}
	registry := l.registry
	if registry == nil {
		registry = windowsRoutePrivateNamespaces
	}
	namespace, err := registry.Acquire(l.alias, l.boundaryName, admins, descriptor)
	runtime.KeepAlive(admins)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return fmt.Errorf("open protected route journal private namespace: %w", err)
	}
	newMutex := l.newMutex
	if newMutex == nil {
		newMutex = func(name string, timeout time.Duration) *namedWindowsRouteJournalLocker {
			return &namedWindowsRouteJournalLocker{name: name, timeout: timeout}
		}
	}
	mutex := newMutex(l.alias+`\`+l.mutexName, l.timeout)
	if err := mutex.Open(); err != nil {
		return errors.Join(err, namespace.Close())
	}
	l.namespace = namespace
	l.mutex = mutex
	return nil
}

func (r *windowsPrivateNamespaceRegistry) Acquire(
	alias, boundaryName string,
	boundarySID *windows.SID,
	descriptor *windows.SECURITY_DESCRIPTOR,
) (*windowsPrivateNamespaceReference, error) {
	identity, err := newWindowsPrivateNamespaceIdentity(alias, boundaryName, boundarySID, descriptor)
	if err != nil {
		return nil, err
	}
	if r == nil || r.open == nil || r.close == nil {
		return nil, errors.New("private namespace registry is not initialized")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]*windowsPrivateNamespaceEntry)
	}
	if entry := r.entries[alias]; entry != nil {
		if entry.identity != identity {
			return nil, fmt.Errorf("private namespace alias %q is already registered with a different boundary or ACL", alias)
		}
		if entry.references <= 0 {
			if entry.closeErr != nil {
				return nil, fmt.Errorf("private namespace alias %q is unavailable after close failure: %w", alias, entry.closeErr)
			}
			return nil, fmt.Errorf("private namespace alias %q has an invalid reference count", alias)
		}
		entry.references++
		return &windowsPrivateNamespaceReference{registry: r, entry: entry}, nil
	}

	namespace, err := r.open(alias, boundaryName, boundarySID, descriptor)
	if err != nil {
		return nil, err
	}
	if namespace == nil {
		return nil, errors.New("private namespace open returned nil without an error")
	}
	entry := &windowsPrivateNamespaceEntry{
		identity:   identity,
		namespace:  namespace,
		references: 1,
	}
	r.entries[alias] = entry
	return &windowsPrivateNamespaceReference{registry: r, entry: entry}, nil
}

func newWindowsPrivateNamespaceIdentity(
	alias, boundaryName string,
	boundarySID *windows.SID,
	descriptor *windows.SECURITY_DESCRIPTOR,
) (windowsPrivateNamespaceIdentity, error) {
	if alias == "" || boundaryName == "" {
		return windowsPrivateNamespaceIdentity{}, errors.New("private namespace alias and boundary name are required")
	}
	if boundarySID == nil || !boundarySID.IsValid() {
		return windowsPrivateNamespaceIdentity{}, errors.New("private namespace boundary SID is missing or invalid")
	}
	if descriptor == nil || !descriptor.IsValid() {
		return windowsPrivateNamespaceIdentity{}, errors.New("private namespace security descriptor is missing or invalid")
	}
	descriptorString := descriptor.String()
	if descriptorString == "" {
		return windowsPrivateNamespaceIdentity{}, errors.New("private namespace security descriptor could not be canonicalized")
	}
	return windowsPrivateNamespaceIdentity{
		alias:        alias,
		boundaryName: boundaryName,
		boundarySID:  boundarySID.String(),
		descriptor:   descriptorString,
	}, nil
}

func (r *windowsPrivateNamespaceRegistry) release(entry *windowsPrivateNamespaceEntry) error {
	if r == nil || entry == nil {
		return errors.New("private namespace reference is invalid")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.entries[entry.identity.alias]
	if current != entry {
		return fmt.Errorf("private namespace alias %q reference is stale", entry.identity.alias)
	}
	if entry.references <= 0 {
		return fmt.Errorf("private namespace alias %q reference count underflow", entry.identity.alias)
	}
	entry.references--
	if entry.references > 0 {
		return nil
	}
	if err := r.close(entry.namespace); err != nil {
		entry.closeErr = err
		return fmt.Errorf("close private namespace alias %q: %w", entry.identity.alias, err)
	}
	delete(r.entries, entry.identity.alias)
	return nil
}

func (r *windowsPrivateNamespaceReference) Close() error {
	if r == nil {
		return nil
	}
	if r.registry == nil || r.entry == nil {
		return errors.New("private namespace reference is invalid")
	}
	r.once.Do(func() {
		r.closeErr = r.registry.release(r.entry)
	})
	return r.closeErr
}

func openWindowsPrivateNamespace(alias, boundaryName string, boundarySID *windows.SID, descriptor *windows.SECURITY_DESCRIPTOR) (*windowsPrivateNamespace, error) {
	for attempt := 0; attempt < windowsPrivateNamespaceOpenTries; attempt++ {
		namespace, err := createOrOpenWindowsPrivateNamespace(alias, boundaryName, boundarySID, descriptor)
		if err == nil {
			return namespace, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("private namespace disappeared during %d open attempts", windowsPrivateNamespaceOpenTries)
}

func openExistingWindowsPrivateNamespace(alias, boundaryName string, boundarySID *windows.SID) (_ *windowsPrivateNamespace, retErr error) {
	boundary, err := createWindowsBoundaryDescriptor(boundaryName, boundarySID)
	if err != nil {
		return nil, err
	}
	closeBoundary := true
	defer func() {
		if closeBoundary {
			deleteWindowsBoundaryDescriptor(boundary)
		}
	}()
	aliasPtr, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return nil, err
	}
	handle, _, callErr := procOpenPrivateNamespaceW.Call(
		uintptr(boundary),
		uintptr(unsafe.Pointer(aliasPtr)),
	)
	runtime.KeepAlive(boundarySID)
	if handle == 0 {
		return nil, fmt.Errorf("OpenPrivateNamespaceW %q: %w", alias, windowsCallError(callErr))
	}
	closeBoundary = false
	return &windowsPrivateNamespace{handle: windows.Handle(handle), boundary: boundary}, nil
}

func createOrOpenWindowsPrivateNamespace(alias, boundaryName string, boundarySID *windows.SID, descriptor *windows.SECURITY_DESCRIPTOR) (_ *windowsPrivateNamespace, retErr error) {
	defer runtime.KeepAlive(boundarySID)
	boundary, err := createWindowsBoundaryDescriptor(boundaryName, boundarySID)
	if err != nil {
		return nil, err
	}
	closeBoundary := true
	defer func() {
		if closeBoundary {
			deleteWindowsBoundaryDescriptor(boundary)
		}
	}()

	aliasPtr, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return nil, err
	}
	var security *windows.SecurityAttributes
	if descriptor != nil {
		security = &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		}
	}
	handle, _, callErr := procCreatePrivateNamespaceW.Call(
		uintptr(unsafe.Pointer(security)),
		uintptr(boundary),
		uintptr(unsafe.Pointer(aliasPtr)),
	)
	runtime.KeepAlive(security)
	runtime.KeepAlive(descriptor)
	if handle == 0 {
		if !errors.Is(callErr, windows.ERROR_ALREADY_EXISTS) {
			return nil, fmt.Errorf("CreatePrivateNamespaceW %q: %w", alias, windowsCallError(callErr))
		}
		handle, _, callErr = procOpenPrivateNamespaceW.Call(
			uintptr(boundary),
			uintptr(unsafe.Pointer(aliasPtr)),
		)
		if handle == 0 {
			return nil, fmt.Errorf("OpenPrivateNamespaceW %q: %w", alias, windowsCallError(callErr))
		}
	}
	closeBoundary = false
	return &windowsPrivateNamespace{handle: windows.Handle(handle), boundary: boundary}, nil
}

func createWindowsBoundaryDescriptor(name string, sid *windows.SID) (windows.Handle, error) {
	if sid == nil || !sid.IsValid() {
		return 0, errors.New("private namespace boundary SID is missing or invalid")
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	value, _, callErr := procCreateBoundaryDescriptorW.Call(uintptr(unsafe.Pointer(namePtr)), 0)
	if value == 0 {
		return 0, fmt.Errorf("CreateBoundaryDescriptorW %q: %w", name, windowsCallError(callErr))
	}
	boundary := windows.Handle(value)
	result, _, callErr := procAddSIDToBoundaryDescriptor.Call(
		uintptr(unsafe.Pointer(&boundary)),
		uintptr(unsafe.Pointer(sid)),
	)
	runtime.KeepAlive(sid)
	if result == 0 {
		deleteWindowsBoundaryDescriptor(boundary)
		return 0, fmt.Errorf("AddSIDToBoundaryDescriptor %q: %w", name, windowsCallError(callErr))
	}
	return boundary, nil
}

func deleteWindowsBoundaryDescriptor(boundary windows.Handle) {
	if boundary != 0 {
		procDeleteBoundaryDescriptor.Call(uintptr(boundary))
	}
}

func (n *windowsPrivateNamespace) Close(destroy bool) error {
	if n == nil {
		return nil
	}
	var closeErr error
	if n.handle != 0 {
		flags := uintptr(0)
		if destroy {
			flags = windowsPrivateNamespaceDestroy
		}
		result, _, callErr := procClosePrivateNamespace.Call(uintptr(n.handle), flags)
		if result == 0 {
			closeErr = fmt.Errorf("ClosePrivateNamespace: %w", windowsCallError(callErr))
		}
		n.handle = 0
	}
	deleteWindowsBoundaryDescriptor(n.boundary)
	n.boundary = 0
	return closeErr
}

func newWindowsRouteNamespaceSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")
}

func windowsCallError(err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return windows.ERROR_INVALID_FUNCTION
	}
	return err
}
