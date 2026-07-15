//go:build windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
}

func SelectiveRoutesSupported() bool { return true }

func newPlatformRouteOperator(interfaceName string, interfaceLUID uint64) (routeOperator, error) {
	if interfaceLUID == 0 {
		return nil, fmt.Errorf("selective routes require the stable Wintun interface LUID")
	}
	api := systemWindowsRouteAPI()
	index, err := api.toIndex(interfaceLUID)
	if err != nil {
		return nil, fmt.Errorf("resolve Wintun LUID %d to interface index: %w", interfaceLUID, err)
	}
	return &windowsRouteOperator{
		interfaceName: interfaceName,
		interfaceLUID: interfaceLUID,
		interfaceIdx:  index,
		api:           api,
		journal:       newWindowsRouteJournal(defaultWindowsRouteJournalPath()),
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

func (o *windowsRouteOperator) Add(ctx context.Context, prefix netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	row := o.routeRow(prefix)
	err := o.api.create(&row)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return errors.Join(ErrRouteAlreadyExists, err)
	}
	if err != nil {
		return fmt.Errorf("CreateIpForwardEntry2: %w", err)
	}
	return ctx.Err()
}

func (o *windowsRouteOperator) Delete(ctx context.Context, prefix netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	row := o.routeRow(prefix)
	if err := o.api.get(&row); err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("GetIpForwardEntry2 before delete: %w", err)
	}
	want := o.routeRow(prefix)
	if !windowsRouteRowsMatch(row, want) {
		return fmt.Errorf("route no longer matches Tachyon-owned attributes")
	}
	if err := o.api.delete(&row); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("DeleteIpForwardEntry2: %w", err)
	}
	return ctx.Err()
}

func (o *windowsRouteOperator) routeRow(prefix netip.Prefix) windows.MibIpForwardRow2 {
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
	row.Metric = windowsRouteMetric
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

func (o *windowsRouteOperator) PrepareOwnership(prefix netip.Prefix) error {
	return o.journal.prepare(o, prefix)
}

func (o *windowsRouteOperator) ReleaseOwnership(prefix netip.Prefix) error {
	return o.journal.release(o, prefix)
}
