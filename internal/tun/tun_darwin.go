//go:build darwin

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// darwinTUN implements Device using the macOS utun socket interface.
//
// macOS exposes TUN-like functionality through AF_SYSTEM + SYSPROTO_CONTROL
// sockets bound to the "com.apple.net.utun_control" kernel control.
// Each socket corresponds to one utun<N> interface.
//
// No external dependencies required — pure syscall.
type darwinTUN struct {
	conn  *os.File
	name  string
	addrs []netip.Prefix
	mtu   int
}

const (
	afSystem        = syscall.AF_SYSTEM // 32
	sysProtoControl = 2                 // SYSPROTO_CONTROL
	afSysAddrCtl    = 2                 // AF_SYS_CONTROL
	ctlIOCGInfo     = 0xc0644e03        // CTLIOCGINFO
	utunControlName = "com.apple.net.utun_control"
	utunOptIFName   = 2 // UTUN_OPT_IFNAME
)

// sockaddrCtl mirrors struct sockaddr_ctl from <sys/kern_control.h>.
type sockaddrCtl struct {
	SCLen      uint8
	SCFamily   uint8
	SSSysaddr  uint16
	SCID       uint32
	SCUnit     uint32
	SCReserved [5]uint32
}

// ctlInfo mirrors struct ctl_info from <sys/kern_control.h>.
type ctlInfo struct {
	CtlID   uint32
	CtlName [96]byte
}

func newDevice(opts Options) (Device, error) {
	// Create the control socket.
	fd, err := syscall.Socket(afSystem, syscall.SOCK_DGRAM, sysProtoControl)
	if err != nil {
		return nil, fmt.Errorf("socket AF_SYSTEM: %w", err)
	}

	// Resolve the utun kernel control ID.
	info := ctlInfo{}
	copy(info.CtlName[:], utunControlName)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		ctlIOCGInfo,
		uintptr(unsafe.Pointer(&info)),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO: %w", errno)
	}

	// Connect to the utun control, requesting the next available unit.
	addr := sockaddrCtl{
		SCLen:     uint8(unsafe.Sizeof(sockaddrCtl{})),
		SCFamily:  afSystem,
		SSSysaddr: afSysAddrCtl,
		SCID:      info.CtlID,
		SCUnit:    0, // 0 = kernel assigns the next free unit
	}
	_, _, errno = syscall.Syscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Sizeof(addr)),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("connect utun: %w", errno)
	}

	// Retrieve the assigned interface name (e.g. "utun9").
	var ifName [16]byte
	ifNameLen := uint32(len(ifName))
	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		sysProtoControl,
		utunOptIFName,
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameLen)),
		0,
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %w", errno)
	}
	name := nullTerminated(ifName[:ifNameLen])

	mtu := opts.mtu()
	f := os.NewFile(uintptr(fd), name)

	// Configure addresses and routes using ifconfig / route.
	for _, addr := range opts.Addresses {
		if addr.Addr().Is4() {
			if err := runIfconfig(name, addr.Addr().String(), broadcastFor(addr), "up"); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("ifconfig: %w", err)
			}
		}
	}

	if err := setMTUDarwin(name, mtu); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("set mtu: %w", err)
	}

	return &darwinTUN{
		conn:  f,
		name:  name,
		addrs: opts.Addresses,
		mtu:   mtu,
	}, nil
}

func (t *darwinTUN) Name() string              { return t.name }
func (t *darwinTUN) Addresses() []netip.Prefix { return t.addrs }
func (t *darwinTUN) MTU() int                  { return t.mtu }

// ReadPacket reads one IPv4/IPv6 packet. The utun prepends a 4-byte AF header
// (big-endian address family); we strip it before returning.
func (t *darwinTUN) ReadPacket(buf []byte) (int, error) {
	tmp := make([]byte, len(buf)+4)
	n, err := t.conn.Read(tmp)
	if err != nil || n <= 4 {
		return 0, err
	}
	return copy(buf, tmp[4:n]), nil
}

// WritePacket injects a raw IP packet. The utun expects the same 4-byte AF header.
func (t *darwinTUN) WritePacket(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	// Determine address family from the IP version nibble.
	af := [4]byte{0, 0, 0, syscall.AF_INET}
	if buf[0]>>4 == 6 {
		af[3] = syscall.AF_INET6
	}
	full := make([]byte, 4+len(buf))
	copy(full[:4], af[:])
	copy(full[4:], buf)
	_, err := t.conn.Write(full)
	return err
}

func (t *darwinTUN) Close() error { return t.conn.Close() }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func broadcastFor(prefix netip.Prefix) string {
	// Compute broadcast: host bits all 1.
	ip := prefix.Addr().As4()
	mask := net.CIDRMask(prefix.Bits(), 32)
	for i := range ip {
		ip[i] |= ^mask[i]
	}
	return net.IP(ip[:]).String()
}

func runIfconfig(args ...string) error {
	return execCommand("/sbin/ifconfig", args...)
}

func setMTUDarwin(iface string, mtu int) error {
	return runIfconfig(iface, "mtu", fmt.Sprintf("%d", mtu))
}
