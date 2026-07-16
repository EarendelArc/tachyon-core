//go:build windows

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

// windowsTUN implements Device using the Wintun C API loaded from wintun.dll.
// The DLL must be available next to tachyon-core.exe or on PATH, and adapter
// creation/configuration requires Administrator privileges.
type windowsTUN struct {
	api           *wintunAPI
	adapter       uintptr
	session       uintptr
	readWaitEvent syscall.Handle
	name          string
	luid          uint64
	addrs         []netip.Prefix
	mtu           int
	writeMu       sync.Mutex
	closeOnce     sync.Once
	closeErr      error
	registered    bool
}

type wintunAPI struct {
	createAdapter        *syscall.LazyProc
	openAdapter          *syscall.LazyProc
	closeAdapter         *syscall.LazyProc
	startSession         *syscall.LazyProc
	endSession           *syscall.LazyProc
	getReadWaitEvent     *syscall.LazyProc
	receivePacket        *syscall.LazyProc
	releaseReceivePacket *syscall.LazyProc
	allocateSendPacket   *syscall.LazyProc
	sendPacket           *syscall.LazyProc
	getAdapterLUID       *syscall.LazyProc
}

const (
	defaultWindowsTUNName = "Tachyon"
	wintunRingCapacity    = 0x400000
	errorNoMoreItems      = syscall.Errno(259)
	errorHandleEOF        = syscall.Errno(38)
)

func newDevice(opts Options) (Device, error) {
	api, err := loadWintunAPI()
	if err != nil {
		return nil, err
	}

	name := opts.Name
	if name == "" {
		name = defaultWindowsTUNName
	}
	adapter, err := api.createOrOpenAdapter(name)
	if err != nil {
		return nil, err
	}

	var luid uint64
	api.getAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&luid)))
	if luid == 0 {
		api.closeAdapter.Call(adapter)
		return nil, fmt.Errorf("WintunGetAdapterLUID returned zero")
	}

	mtu := opts.mtu()
	tun := &windowsTUN{
		api:     api,
		adapter: adapter,
		name:    name,
		luid:    luid,
		addrs:   append([]netip.Prefix(nil), opts.Addresses...),
		mtu:     mtu,
	}
	if err := tun.startSession(); err != nil {
		_ = tun.Close()
		return nil, err
	}
	if err := configureWindowsInterface(name, opts.Addresses, mtu); err != nil {
		_ = tun.Close()
		return nil, err
	}
	registerCurrentWindowsAdapter(luid)
	tun.registered = true
	return tun, nil
}

func (t *windowsTUN) Name() string                { return t.name }
func (t *windowsTUN) Addresses() []netip.Prefix   { return append([]netip.Prefix(nil), t.addrs...) }
func (t *windowsTUN) MTU() int                    { return t.mtu }
func (t *windowsTUN) stableInterfaceLUID() uint64 { return t.luid }

func (t *windowsTUN) ReadPacket(buf []byte) (int, error) {
	for {
		var size uint32
		packet, _, callErr := t.api.receivePacket.Call(
			t.session,
			uintptr(unsafe.Pointer(&size)),
		)
		if packet != 0 {
			if int(size) > len(buf) {
				t.api.releaseReceivePacket.Call(t.session, packet)
				return 0, fmt.Errorf("packet size %d exceeds buffer size %d", size, len(buf))
			}
			copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(packet)), int(size)))
			t.api.releaseReceivePacket.Call(t.session, packet)
			return int(size), nil
		}

		err := syscallErr(callErr)
		if errors.Is(err, errorNoMoreItems) {
			if ret, waitErr := syscall.WaitForSingleObject(t.readWaitEvent, syscall.INFINITE); ret != 0 {
				return 0, fmt.Errorf("wait for wintun packet: ret=%d err=%w", ret, waitErr)
			}
			continue
		}
		if errors.Is(err, errorHandleEOF) {
			return 0, os.ErrClosed
		}
		return 0, fmt.Errorf("WintunReceivePacket: %w", err)
	}
}

func (t *windowsTUN) WritePacket(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	packet, _, callErr := t.api.allocateSendPacket.Call(t.session, uintptr(len(buf)))
	if packet == 0 {
		return fmt.Errorf("WintunAllocateSendPacket: %w", syscallErr(callErr))
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(packet)), len(buf)), buf)
	t.api.sendPacket.Call(t.session, packet)
	return nil
}

func (t *windowsTUN) Close() error {
	t.closeOnce.Do(func() {
		if t.registered {
			unregisterCurrentWindowsAdapter(t.luid)
			t.registered = false
		}
		if t.session != 0 {
			t.api.endSession.Call(t.session)
		}
		if t.adapter != 0 {
			t.api.closeAdapter.Call(t.adapter)
		}
	})
	return t.closeErr
}

func (t *windowsTUN) startSession() error {
	session, _, err := t.api.startSession.Call(t.adapter, uintptr(wintunRingCapacity))
	if session == 0 {
		return fmt.Errorf("WintunStartSession: %w", syscallErr(err))
	}
	event, _, err := t.api.getReadWaitEvent.Call(session)
	if event == 0 {
		t.api.endSession.Call(session)
		return fmt.Errorf("WintunGetReadWaitEvent: %w", syscallErr(err))
	}
	t.session = session
	t.readWaitEvent = syscall.Handle(event)
	return nil
}

func loadWintunAPI() (*wintunAPI, error) {
	dll := syscall.NewLazyDLL("wintun.dll")
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("load wintun.dll: %w (place wintun.dll next to tachyon-core.exe or on PATH)", err)
	}
	api := &wintunAPI{
		createAdapter:        dll.NewProc("WintunCreateAdapter"),
		openAdapter:          dll.NewProc("WintunOpenAdapter"),
		closeAdapter:         dll.NewProc("WintunCloseAdapter"),
		startSession:         dll.NewProc("WintunStartSession"),
		endSession:           dll.NewProc("WintunEndSession"),
		getReadWaitEvent:     dll.NewProc("WintunGetReadWaitEvent"),
		receivePacket:        dll.NewProc("WintunReceivePacket"),
		releaseReceivePacket: dll.NewProc("WintunReleaseReceivePacket"),
		allocateSendPacket:   dll.NewProc("WintunAllocateSendPacket"),
		sendPacket:           dll.NewProc("WintunSendPacket"),
		getAdapterLUID:       dll.NewProc("WintunGetAdapterLUID"),
	}
	for name, proc := range map[string]*syscall.LazyProc{
		"WintunCreateAdapter":        api.createAdapter,
		"WintunOpenAdapter":          api.openAdapter,
		"WintunCloseAdapter":         api.closeAdapter,
		"WintunStartSession":         api.startSession,
		"WintunEndSession":           api.endSession,
		"WintunGetReadWaitEvent":     api.getReadWaitEvent,
		"WintunReceivePacket":        api.receivePacket,
		"WintunReleaseReceivePacket": api.releaseReceivePacket,
		"WintunAllocateSendPacket":   api.allocateSendPacket,
		"WintunSendPacket":           api.sendPacket,
		"WintunGetAdapterLUID":       api.getAdapterLUID,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("find %s in wintun.dll: %w", name, err)
		}
	}
	return api, nil
}

func (api *wintunAPI) createOrOpenAdapter(name string) (uintptr, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	tunnelTypePtr, err := syscall.UTF16PtrFromString("Tachyon")
	if err != nil {
		return 0, err
	}
	adapter, _, createErr := api.createAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(tunnelTypePtr)),
		0,
	)
	if adapter != 0 {
		return adapter, nil
	}

	adapter, _, openErr := api.openAdapter.Call(uintptr(unsafe.Pointer(namePtr)))
	if adapter != 0 {
		return adapter, nil
	}
	return 0, fmt.Errorf("WintunCreateAdapter: %w; WintunOpenAdapter: %w", syscallErr(createErr), syscallErr(openErr))
}

func configureWindowsInterface(name string, addrs []netip.Prefix, mtu int) error {
	if err := setWindowsMTU(name, mtu); err != nil {
		return err
	}
	for _, prefix := range addrs {
		if err := addWindowsAddress(name, prefix); err != nil {
			return err
		}
	}
	return nil
}

func setWindowsMTU(name string, mtu int) error {
	value := strconv.Itoa(mtu)
	if err := runNetsh("interface", "ipv4", "set", "subinterface", name, "mtu="+value, "store=active"); err != nil {
		return fmt.Errorf("set IPv4 MTU: %w", err)
	}
	_ = runNetsh("interface", "ipv6", "set", "subinterface", name, "mtu="+value, "store=active")
	return nil
}

func addWindowsAddress(name string, prefix netip.Prefix) error {
	args, err := windowsAddressArgs(name, prefix)
	if err != nil {
		return err
	}
	return runNetsh(args...)
}

func windowsAddressArgs(name string, prefix netip.Prefix) ([]string, error) {
	if prefix.Addr().Is4() {
		mask, err := ipv4Mask(prefix)
		if err != nil {
			return nil, err
		}
		return []string{
			"interface", "ipv4", "add", "address",
			"name=" + name,
			"address=" + prefix.Addr().String(),
			"mask=" + mask,
			"store=active",
		}, nil
	}
	return []string{
		"interface", "ipv6", "add", "address",
		"interface=" + name,
		"address=" + prefix.String(),
		"store=active",
	}, nil
}

func ipv4Mask(prefix netip.Prefix) (string, error) {
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("prefix is not IPv4: %s", prefix)
	}
	mask := net.CIDRMask(prefix.Bits(), 32)
	if mask == nil {
		return "", fmt.Errorf("invalid IPv4 prefix: %s", prefix)
	}
	return net.IP(mask).String(), nil
}

func runNetsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v: %w: %s", args, err, string(output))
	}
	return nil
}

func syscallErr(err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return syscall.EINVAL
	}
	return err
}
