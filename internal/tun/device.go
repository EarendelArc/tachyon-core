// Package tun provides cross-platform TUN virtual network device management.
//
// Architecture:
//
//	TUNDevice (interface)
//	├── linuxTUN   — /dev/tun + netlink  (tun_linux.go)
//	├── darwinTUN  — utun socket         (tun_darwin.go)
//	└── windowsTUN — wintun.dll          (tun_windows.go)
//
// A TUN device receives raw IPv4/IPv6 packets from the OS kernel. The TUN
// pipeline reads these packets, passes them to the userspace TCP/IP stack
// (gVisor netstack), which reconstructs TCP/UDP streams. The routing engine
// then decides whether to forward each flow via Xray or TGP.
//
// Ownership model: the caller owns the TUNDevice and must call Close when done.
// Closing the device releases the OS interface and stops all packet reads.
package tun

import (
	"net/netip"
)

// Device is the cross-platform abstraction over a TUN virtual network interface.
// All methods are safe for concurrent use.
type Device interface {
	// Name returns the OS-assigned interface name (e.g. "tachyon0", "utun9").
	Name() string

	// Addresses returns the IPv4/IPv6 CIDRs assigned to this interface.
	Addresses() []netip.Prefix

	// MTU returns the maximum transmission unit of this interface.
	MTU() int

	// ReadPacket reads one raw IP packet from the OS into buf.
	// Returns the number of bytes written. Blocks until a packet is available
	// or the device is closed.
	ReadPacket(buf []byte) (int, error)

	// WritePacket writes one raw IP packet to the OS (i.e. injects it into
	// the kernel network stack as if it arrived on this interface).
	WritePacket(buf []byte) error

	// Close removes the TUN interface from the OS and releases all resources.
	Close() error
}

// Options configures a TUN device at creation time.
type Options struct {
	// Name is the desired interface name. An empty string lets the OS choose.
	Name string

	// Addresses is the list of IPv4/IPv6 CIDRs to assign to the interface.
	Addresses []netip.Prefix

	// MTU defaults to 9000 if zero.
	MTU int

	// AutoRoute installs a default route (0.0.0.0/0) pointing at this interface.
	AutoRoute bool

	// DNSHijack adds a rule that forwards UDP/53 through the TUN pipeline.
	DNSHijack bool
}

// DefaultMTU is used when Options.MTU is zero.
const DefaultMTU = 9000

func (o *Options) mtu() int {
	if o.MTU == 0 {
		return DefaultMTU
	}
	return o.MTU
}

// New creates a TUN device using the platform-specific implementation.
// The returned device is ready to read/write packets immediately.
func New(opts Options) (Device, error) {
	return newDevice(opts)
}
