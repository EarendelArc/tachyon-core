//go:build windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsRouteMetric   = 1
	windowsRouteProtocol = windows.MIB_IPPROTO_NETMGMT
)

var (
	ipHelperDLL                   = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardEntry  = ipHelperDLL.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2     = ipHelperDLL.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2     = ipHelperDLL.NewProc("DeleteIpForwardEntry2")
	procConvertLUIDToInterfaceIdx = ipHelperDLL.NewProc("ConvertInterfaceLuidToIndex")
)

type windowsRouteAPI struct {
	get       func(*windows.MibIpForwardRow2) error
	create    func(*windows.MibIpForwardRow2) error
	delete    func(*windows.MibIpForwardRow2) error
	toIndex   func(uint64) (uint32, error)
	initEntry func(*windows.MibIpForwardRow2)
}

type windowsRouteOperator struct {
	interfaceName string
	interfaceLUID uint64
	interfaceIdx  uint32
	api           windowsRouteAPI
	journal       *windowsRouteJournal
	transition    *windowsRouteJournalTransition
	adapterOwned  func() bool
}

var currentWindowsAdapters = struct {
	sync.Mutex
	luids map[uint64]uint32
}{luids: make(map[uint64]uint32)}

func SelectiveRoutesSupported() bool { return true }

func newPlatformRouteOperator(interfaceName string, interfaceLUID uint64) (routeOperator, error) {
	if interfaceLUID == 0 {
		return nil, fmt.Errorf("selective routes require the stable Wintun interface LUID")
	}
	if !windowsAdapterOwnedByCurrentProcess(interfaceLUID) {
		return nil, fmt.Errorf("selective routes require a Wintun adapter owned by the current process")
	}
	api := systemWindowsRouteAPI()
	index, err := api.toIndex(interfaceLUID)
	if err != nil {
		return nil, fmt.Errorf("resolve Wintun LUID %d to interface index: %w", interfaceLUID, err)
	}
	journal, err := newDefaultWindowsRouteJournal()
	if err != nil {
		return nil, err
	}
	return &windowsRouteOperator{
		interfaceName: interfaceName,
		interfaceLUID: interfaceLUID,
		interfaceIdx:  index,
		api:           api,
		journal:       journal,
		adapterOwned:  func() bool { return windowsAdapterOwnedByCurrentProcess(interfaceLUID) },
	}, nil
}

func systemWindowsRouteAPI() windowsRouteAPI {
	return windowsRouteAPI{
		get:       windows.GetIpForwardEntry2,
		create:    createIpForwardEntry2,
		delete:    deleteIpForwardEntry2,
		toIndex:   convertInterfaceLUIDToIndex,
		initEntry: initializeIpForwardEntry,
	}
}

func (o *windowsRouteOperator) Read(ctx context.Context, prefix netip.Prefix) (routeState, error) {
	if err := ctx.Err(); err != nil {
		return routeState{}, err
	}
	want := o.routeRow(prefix)
	got := want
	err := o.api.get(&got)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return routeState{}, nil
	}
	if err != nil {
		return routeState{}, fmt.Errorf("GetIpForwardEntry2: %w", err)
	}
	return routeState{Exists: true, Matches: windowsRouteRowsMatch(got, want)}, nil
}

func (o *windowsRouteOperator) Add(ctx context.Context, prefix netip.Prefix) (routeAddResult, error) {
	if err := ctx.Err(); err != nil {
		return routeAddResult{}, err
	}
	row := o.routeRow(prefix)
	err := o.api.create(&row)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return routeAddResult{}, errors.Join(ErrRouteAlreadyExists, err)
	}
	if err != nil {
		return routeAddResult{}, fmt.Errorf("CreateIpForwardEntry2: %w", err)
	}
	return routeAddResult{Committed: true}, ctx.Err()
}

func (o *windowsRouteOperator) Delete(ctx context.Context, prefix netip.Prefix) (routeDeleteResult, error) {
	if err := ctx.Err(); err != nil {
		return routeDeleteResult{}, err
	}
	// DeleteIpForwardEntry2 has no compare-delete primitive. The ownership
	// store must hold the protected machine lock across this read and delete.
	row := o.routeRow(prefix)
	if err := o.api.get(&row); err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			return routeDeleteResult{}, nil
		}
		return routeDeleteResult{}, fmt.Errorf("GetIpForwardEntry2 before delete: %w", err)
	}
	want := o.routeRow(prefix)
	if !windowsRouteRowsMatch(row, want) {
		return routeDeleteResult{}, fmt.Errorf("route no longer matches Tachyon-owned attributes")
	}
	if err := o.api.delete(&row); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return routeDeleteResult{}, fmt.Errorf("DeleteIpForwardEntry2: %w", err)
	}
	return routeDeleteResult{Committed: true}, ctx.Err()
}

func (o *windowsRouteOperator) routeRow(prefix netip.Prefix) windows.MibIpForwardRow2 {
	return o.routeRowWithMetric(prefix, windowsRouteMetric)
}

func registerCurrentWindowsAdapter(luid uint64) {
	currentWindowsAdapters.Lock()
	defer currentWindowsAdapters.Unlock()
	currentWindowsAdapters.luids[luid]++
}

func unregisterCurrentWindowsAdapter(luid uint64) {
	currentWindowsAdapters.Lock()
	defer currentWindowsAdapters.Unlock()
	if currentWindowsAdapters.luids[luid] <= 1 {
		delete(currentWindowsAdapters.luids, luid)
		return
	}
	currentWindowsAdapters.luids[luid]--
}

func windowsAdapterOwnedByCurrentProcess(luid uint64) bool {
	currentWindowsAdapters.Lock()
	defer currentWindowsAdapters.Unlock()
	return currentWindowsAdapters.luids[luid] != 0
}

func (o *windowsRouteOperator) adapterOwnershipProven() bool {
	return o.adapterOwned == nil || o.adapterOwned()
}

func (o *windowsRouteOperator) routeRowWithMetric(prefix netip.Prefix, metric uint32) windows.MibIpForwardRow2 {
	prefix = prefix.Masked()
	var row windows.MibIpForwardRow2
	o.api.initEntry(&row)
	row.InterfaceLuid = o.interfaceLUID
	row.InterfaceIndex = o.interfaceIdx
	row.DestinationPrefix = windows.IpAddressPrefix{
		Prefix:       rawSockaddrInet(prefix.Addr()),
		PrefixLength: uint8(prefix.Bits()),
	}
	if prefix.Addr().Is4() {
		row.NextHop = rawSockaddrInet(netip.IPv4Unspecified())
	} else {
		row.NextHop = rawSockaddrInet(netip.IPv6Unspecified())
	}
	row.Metric = metric
	row.Protocol = windowsRouteProtocol
	return row
}

func windowsRouteRowsMatch(got, want windows.MibIpForwardRow2) bool {
	return got.InterfaceLuid == want.InterfaceLuid &&
		got.InterfaceIndex == want.InterfaceIndex &&
		got.DestinationPrefix.PrefixLength == want.DestinationPrefix.PrefixLength &&
		got.DestinationPrefix.Prefix == want.DestinationPrefix.Prefix &&
		got.NextHop == want.NextHop &&
		got.Metric == want.Metric &&
		got.Protocol == want.Protocol
}

func rawSockaddrInet(addr netip.Addr) windows.RawSockaddrInet {
	addr = addr.Unmap()
	var raw windows.RawSockaddrInet
	if addr.Is4() {
		value := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: addr.As4()}
		*(*windows.RawSockaddrInet4)(unsafe.Pointer(&raw)) = value
		return raw
	}
	value := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: addr.As16()}
	*(*windows.RawSockaddrInet6)(unsafe.Pointer(&raw)) = value
	return raw
}

func initializeIpForwardEntry(row *windows.MibIpForwardRow2) {
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
}

func createIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	result, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return windowsStatus(result)
}

func deleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	result, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return windowsStatus(result)
}

func convertInterfaceLUIDToIndex(luid uint64) (uint32, error) {
	var index uint32
	result, _, _ := procConvertLUIDToInterfaceIdx.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&index)),
	)
	if err := windowsStatus(result); err != nil {
		return 0, err
	}
	return index, nil
}

func windowsStatus(result uintptr) error {
	if result == 0 {
		return nil
	}
	return syscall.Errno(result)
}

func (o *windowsRouteOperator) Reconcile(ctx context.Context) error {
	return o.journal.reconcile(ctx, o)
}

func (o *windowsRouteOperator) RecordOwnership(prefix netip.Prefix) error {
	return o.journal.record(o, prefix)
}

func (o *windowsRouteOperator) PrepareOwnership(ctx context.Context, prefix netip.Prefix) error {
	return o.journal.prepare(ctx, o, prefix)
}

func (o *windowsRouteOperator) ReleaseOwnership(prefix netip.Prefix) error {
	return o.journal.release(o, prefix)
}

func (o *windowsRouteOperator) PrepareDeletion(ctx context.Context, prefix netip.Prefix) error {
	return o.journal.prepareDeletion(ctx, o, prefix)
}

func (o *windowsRouteOperator) Close() error {
	if o.transition != nil {
		return errors.New("cannot close Windows route operator during a journal transition")
	}
	return o.journal.Close()
}

type windowsRouteOwnershipRecordError struct {
	err        error
	rolledBack bool
}

func (e *windowsRouteOwnershipRecordError) Error() string { return e.err.Error() }
func (e *windowsRouteOwnershipRecordError) Unwrap() error { return e.err }
func (e *windowsRouteOwnershipRecordError) RouteRolledBack() bool {
	return e.rolledBack
}
