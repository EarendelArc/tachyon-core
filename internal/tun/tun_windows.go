//go:build windows

package tun

import (
	"fmt"
	"net/netip"
)

// windowsTUN implements Device using the Wintun driver.
//
// Wintun (https://www.wintun.net/) is a layer-3 TUN driver for Windows
// developed by WireGuard. It provides a ring-buffer DMA interface that avoids
// NDIS overhead, achieving much higher throughput than the legacy TAP driver.
//
// IMPORTANT: Creating a Wintun adapter requires Administrator privileges.
// The recommended approach (following WireGuard-Windows) is to split privileges:
//   - tachyon-helper.exe runs as a Windows Service with LocalSystem rights
//     and owns the Wintun adapter lifecycle.
//   - tachyon-core runs as the user and communicates with the helper via
//     a named pipe to obtain the Wintun ring buffer handles.
//
// This file contains the stub for the direct (same-process, elevated) path.
// The helper-based path is in launcher/windows_helper.go (future milestone).
//
// Dependencies (add to go.mod when implementing):
//   golang.zx2c4.com/wintun
type windowsTUN struct {
	name  string
	addrs []netip.Prefix
	mtu   int
	// adapter *wintun.Adapter  — uncomment when wintun dependency is added
	// session  wintun.Session
}

func newDevice(opts Options) (Device, error) {
	// TODO M5: Implement Wintun adapter creation.
	//
	// Steps:
	//  1. wintun.CreateAdapter(opts.Name, "Tachyon", &guid)
	//  2. adapter.StartSession(ringCapacity)
	//  3. Configure MTU: adapter.SetMTU(mtu)
	//  4. Assign IP addresses via iphlpapi: AddIPAddress / CreateUnicastIpAddressEntry
	//  5. Bring link up via MIB_IFROW
	//  6. If opts.AutoRoute: add 0.0.0.0/0 via CreateIpForwardEntry2
	//
	// For now, return a not-implemented error so compilation succeeds.
	return nil, fmt.Errorf("Windows TUN (Wintun) not yet implemented; " +
		"see internal/tun/tun_windows.go for implementation guide")
}

func (t *windowsTUN) Name() string              { return t.name }
func (t *windowsTUN) Addresses() []netip.Prefix { return t.addrs }
func (t *windowsTUN) MTU() int                  { return t.mtu }

func (t *windowsTUN) ReadPacket(buf []byte) (int, error) {
	// TODO: session.ReceivePacket() + copy to buf
	return 0, fmt.Errorf("not implemented")
}

func (t *windowsTUN) WritePacket(buf []byte) error {
	// TODO: pkt := session.AllocateSendPacket(len(buf)); copy; session.SendPacket(pkt)
	return fmt.Errorf("not implemented")
}

func (t *windowsTUN) Close() error {
	// TODO: session.End(); adapter.Close()
	return nil
}
