//go:build windows

package pidtrack

import "testing"

func TestFindUDPOwnerPIDFallsBackToWildcardBinding(t *testing.T) {
	rows := []mibUDPRowOwnerPID{
		{LocalAddr: 0, LocalPort: windowsTablePort(27015), OwningPID: 42},
	}

	pid, ok := findUDPOwnerPID(rows, dotIPToUint32("192.168.1.10"), 27015)
	if !ok || pid != 42 {
		t.Fatalf("findUDPOwnerPID() = (%d, %v), want (42, true)", pid, ok)
	}
}

func TestFindUDPOwnerPIDPrefersExactBinding(t *testing.T) {
	wantIP := dotIPToUint32("192.168.1.10")
	rows := []mibUDPRowOwnerPID{
		{LocalAddr: 0, LocalPort: windowsTablePort(27015), OwningPID: 42},
		{LocalAddr: wantIP, LocalPort: windowsTablePort(27015), OwningPID: 84},
	}

	pid, ok := findUDPOwnerPID(rows, wantIP, 27015)
	if !ok || pid != 84 {
		t.Fatalf("findUDPOwnerPID() = (%d, %v), want (84, true)", pid, ok)
	}
}

func TestFindUDPOwnerPIDRejectsDifferentPort(t *testing.T) {
	rows := []mibUDPRowOwnerPID{
		{LocalAddr: 0, LocalPort: windowsTablePort(27016), OwningPID: 42},
	}

	if pid, ok := findUDPOwnerPID(rows, dotIPToUint32("192.168.1.10"), 27015); ok {
		t.Fatalf("findUDPOwnerPID() = (%d, true), want no match", pid)
	}
}

func windowsTablePort(port uint32) uint32 {
	return (port>>8)&0xff | (port&0xff)<<8
}
