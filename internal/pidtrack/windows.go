//go:build windows

package pidtrack

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"
)

// windowsProvider implements Provider using the Windows IP Helper API (iphlpapi.dll).
//
// Algorithm:
//  1. Call GetExtendedTcpTable / GetExtendedUdpTable with TCP_TABLE_OWNER_PID_ALL
//     to get a table of (local-address, local-port, PID) rows.
//  2. Match the row against FlowKey.LocalIP + LocalPort.
//  3. Call OpenProcess + QueryFullProcessImageNameW to get the executable path.
type windowsProvider struct {
	getTcpTable *syscall.Proc
	getUdpTable *syscall.Proc
	openProcess *syscall.Proc
	queryImg    *syscall.Proc
}

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	processQueryLimited = 0x1000
	afInet              = 2
)

func newProvider() (Provider, error) {
	iphlp, err := syscall.LoadDLL("iphlpapi.dll")
	if err != nil {
		return nil, fmt.Errorf("load iphlpapi.dll: %w", err)
	}
	kern, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return nil, fmt.Errorf("load kernel32.dll: %w", err)
	}
	getTcp, err := iphlp.FindProc("GetExtendedTcpTable")
	if err != nil {
		return nil, fmt.Errorf("GetExtendedTcpTable: %w", err)
	}
	getUdp, err := iphlp.FindProc("GetExtendedUdpTable")
	if err != nil {
		return nil, fmt.Errorf("GetExtendedUdpTable: %w", err)
	}
	open, err := kern.FindProc("OpenProcess")
	if err != nil {
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	query, err := kern.FindProc("QueryFullProcessImageNameW")
	if err != nil {
		return nil, fmt.Errorf("QueryFullProcessImageNameW: %w", err)
	}
	return &windowsProvider{
		getTcpTable: getTcp,
		getUdpTable: getUdp,
		openProcess: open,
		queryImg:    query,
	}, nil
}

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// LookupByFlow resolves a FlowKey to a ProcessInfo via the Windows IP helper API.
func (p *windowsProvider) LookupByFlow(_ context.Context, flow FlowKey) (ProcessInfo, error) {
	if flow.Transport == TransportTCP {
		return p.lookupTCP(flow)
	}
	return p.lookupUDP(flow)
}

// LookupPID returns process information for a given PID.
func (p *windowsProvider) LookupPID(_ context.Context, pid int) (ProcessInfo, error) {
	return p.pidToProcessInfo(pid)
}

func (p *windowsProvider) lookupTCP(flow FlowKey) (ProcessInfo, error) {
	wantIP := dotIPToUint32(flow.LocalIP)
	wantPort := uint32(flow.LocalPort)

	bufSize := uint32(8192)
	for {
		buf := make([]byte, bufSize)
		ret, _, _ := p.getTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufSize)),
			0, uintptr(afInet), uintptr(tcpTableOwnerPIDAll), 0,
		)
		if ret == uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if ret != 0 {
			return ProcessInfo{}, fmt.Errorf("GetExtendedTcpTable error %d", ret)
		}
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		rows := (*[1 << 16]mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4]))[:count]
		for _, row := range rows {
			rowPort := swapPort(row.LocalPort)
			if row.LocalAddr == wantIP && rowPort == wantPort {
				return p.pidToProcessInfo(int(row.OwningPID))
			}
		}
		return ProcessInfo{}, fmt.Errorf("TCP socket %s:%d not found", flow.LocalIP, flow.LocalPort)
	}
}

func (p *windowsProvider) lookupUDP(flow FlowKey) (ProcessInfo, error) {
	wantIP := dotIPToUint32(flow.LocalIP)
	wantPort := uint32(flow.LocalPort)

	bufSize := uint32(8192)
	for {
		buf := make([]byte, bufSize)
		ret, _, _ := p.getUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufSize)),
			0, uintptr(afInet), uintptr(udpTableOwnerPID), 0,
		)
		if ret == uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if ret != 0 {
			return ProcessInfo{}, fmt.Errorf("GetExtendedUdpTable error %d", ret)
		}
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		rows := (*[1 << 16]mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4]))[:count]
		for _, row := range rows {
			rowPort := swapPort(row.LocalPort)
			if row.LocalAddr == wantIP && rowPort == wantPort {
				return p.pidToProcessInfo(int(row.OwningPID))
			}
		}
		return ProcessInfo{}, fmt.Errorf("UDP socket %s:%d not found", flow.LocalIP, flow.LocalPort)
	}
}

func (p *windowsProvider) pidToProcessInfo(pid int) (ProcessInfo, error) {
	handle, _, err := p.openProcess.Call(processQueryLimited, 0, uintptr(pid))
	if handle == 0 {
		return ProcessInfo{}, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	ret, _, err := p.queryImg.Call(handle, 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return ProcessInfo{}, fmt.Errorf("QueryFullProcessImageNameW: %w", err)
	}
	exePath := syscall.UTF16ToString(buf[:size])
	return ProcessInfo{
		PID:            pid,
		Name:           exeBasename(exePath),
		ExecutablePath: exePath,
	}, nil
}

// dotIPToUint32 converts a dotted-decimal IPv4 string to a little-endian uint32
// as stored by the Windows IP helper tables.
func dotIPToUint32(ip string) uint32 {
	var b [4]byte
	n := 0
	for _, part := range splitDot(ip) {
		if n >= 4 {
			break
		}
		v := uint32(0)
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			v = v*10 + uint32(c-'0')
		}
		b[n] = byte(v)
		n++
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// swapPort converts a big-endian port stored as uint32 to a host-order uint32.
func swapPort(p uint32) uint32 {
	return (p>>8)&0xff | (p&0xff)<<8
}

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func exeBasename(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
