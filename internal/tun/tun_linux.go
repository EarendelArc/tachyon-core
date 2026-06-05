//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// linuxTUN implements Device using the Linux /dev/net/tun interface.
// See: https://www.kernel.org/doc/html/latest/networking/tuntap.html
type linuxTUN struct {
	file  *os.File
	name  string
	addrs []netip.Prefix
	mtu   int
}

// ifreqFlags is used with ioctl TUNSETIFF.
type ifreqFlags struct {
	Name  [syscall.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

const (
	tunSetIFF = 0x400454ca
	ifffTun   = 0x0001
	ifffNoPi  = 0x1000
)

func newDevice(opts Options) (Device, error) {
	// Open the TUN cloning device.
	fd, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (run as root or with CAP_NET_ADMIN)", err)
	}

	// Configure the interface.
	var req ifreqFlags
	req.Flags = ifffTun | ifffNoPi // TUN mode, no packet info header
	if opts.Name != "" {
		copy(req.Name[:], opts.Name)
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd.Fd(),
		tunSetIFF,
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		_ = fd.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	ifaceName := nullTerminated(req.Name[:])

	mtu := opts.mtu()
	if err := setMTU(ifaceName, mtu); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("set MTU: %w", err)
	}

	if err := setAddresses(ifaceName, opts.Addresses); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("set addresses: %w", err)
	}

	if err := setLinkUp(ifaceName); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("link up: %w", err)
	}

	if opts.AutoRoute {
		if err := addDefaultRoute(ifaceName); err != nil {
			// Non-fatal: log and continue.
			fmt.Fprintf(os.Stderr, "warn: add default route: %v\n", err)
		}
	}

	return &linuxTUN{
		file:  fd,
		name:  ifaceName,
		addrs: opts.Addresses,
		mtu:   mtu,
	}, nil
}

func (t *linuxTUN) Name() string              { return t.name }
func (t *linuxTUN) Addresses() []netip.Prefix { return t.addrs }
func (t *linuxTUN) MTU() int                  { return t.mtu }

func (t *linuxTUN) ReadPacket(buf []byte) (int, error) {
	return t.file.Read(buf)
}

func (t *linuxTUN) WritePacket(buf []byte) error {
	_, err := t.file.Write(buf)
	return err
}

func (t *linuxTUN) Close() error {
	if t.file != nil {
		return t.file.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// netlink helpers
// ---------------------------------------------------------------------------

func setMTU(iface string, mtu int) error {
	return runIP("link", "set", "dev", iface, "mtu", fmt.Sprintf("%d", mtu))
}

func setAddresses(iface string, addrs []netip.Prefix) error {
	for _, addr := range addrs {
		if err := runIP("addr", "add", addr.String(), "dev", iface); err != nil {
			return err
		}
	}
	return nil
}

func setLinkUp(iface string) error {
	return runIP("link", "set", "dev", iface, "up")
}

func addDefaultRoute(iface string) error {
	// Add routes for both IPv4 and IPv6 if needed.
	_ = runIP("route", "add", "default", "dev", iface)
	return nil
}

func runIP(args ...string) error {
	// Shell out to iproute2 for initial setup. For production, replace
	// with direct netlink calls to eliminate the external dependency.
	cmd := append([]string{"/sbin/ip"}, args...)
	return runCmd(cmd)
}

func runCmd(args []string) error {
	if len(args) == 0 {
		return nil
	}
	// Use os/exec; import is in exec_linux.go to keep this file clean.
	return execCommand(args[0], args[1:]...)
}

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
