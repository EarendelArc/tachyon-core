//go:build linux

package pidtrack

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// linuxProvider implements Provider using /proc/net pseudo-files.
//
// Algorithm (LookupByFlow):
//  1. Read /proc/net/tcp6 or /proc/net/udp6 to build a hex-addr → inode map.
//  2. Walk /proc/*/fd/ symlinks to find which PID owns the matching inode.
//  3. Read /proc/<pid>/comm for the process name.
//  4. Read /proc/<pid>/exe for the full path.
type linuxProvider struct{}

func newProvider() (Provider, error) {
	return &linuxProvider{}, nil
}

// LookupByFlow resolves a FlowKey to a ProcessInfo using /proc pseudo-files.
func (p *linuxProvider) LookupByFlow(_ context.Context, flow FlowKey) (ProcessInfo, error) {
	procFile := "/proc/net/tcp6"
	if flow.Transport == TransportUDP {
		procFile = "/proc/net/udp6"
	}

	inode, err := findInodeInProcNet(procFile, flow.LocalIP, flow.LocalPort)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("inode lookup in %s: %w", procFile, err)
	}

	pid, err := findPIDByInode(inode)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("pid for inode %d: %w", inode, err)
	}

	return p.LookupPID(context.Background(), pid)
}

// LookupPID returns process information for a given PID.
func (p *linuxProvider) LookupPID(_ context.Context, pid int) (ProcessInfo, error) {
	name, err := readComm(pid)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("read comm for pid %d: %w", pid, err)
	}
	exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	ppidStr, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	ppid := parseParentPID(string(ppidStr))

	return ProcessInfo{
		PID:            pid,
		ParentPID:      ppid,
		Name:           name,
		ExecutablePath: exePath,
	}, nil
}

// ---------------------------------------------------------------------------
// /proc/net parsing helpers
// ---------------------------------------------------------------------------

// findInodeInProcNet parses /proc/net/tcp6 (or udp6) to find the socket inode
// for a given local IP + port.
//
// The relevant columns (space-separated):
//
//	sl  local_address rem_address st tx:rx ... uid timeout inode
//
// local_address is hex IPv6 (or IPv4-in-IPv6) followed by :hex-port.
func findInodeInProcNet(path, localIP string, localPort uint16) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	wantHex := ipToHex(localIP)
	wantPort := uint32(localPort)

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		// fields[1] = "hexIP:hexPort"
		parts := strings.SplitN(fields[1], ":", 2)
		if len(parts) != 2 {
			continue
		}
		if !strings.EqualFold(parts[0], wantHex) {
			continue
		}
		port, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil || uint32(port) != wantPort {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		return inode, nil
	}
	return 0, fmt.Errorf("socket %s:%d not found in %s", localIP, localPort, path)
}

// findPIDByInode walks /proc/*/fd to find which process has a symlink to
// "socket:[inode]".
func findPIDByInode(inode uint64) (int, error) {
	target := fmt.Sprintf("socket:[%d]", inode)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("no process found with inode %d", inode)
}

func readComm(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func parseParentPID(status string) int {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.Atoi(fields[1])
				return v
			}
		}
	}
	return 0
}

// ipToHex converts a dotted-decimal IPv4 or colon-hex IPv6 string to the
// hex representation used in /proc/net/tcp6.
// For IPv4, the kernel stores it as a little-endian 32-bit word padded to
// 128 bits (IPv4-in-IPv6).
func ipToHex(ip string) string {
	// Handle IPv4 dotted-decimal
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		var b [4]byte
		for i, p := range parts {
			v, _ := strconv.ParseUint(p, 10, 8)
			b[i] = byte(v)
		}
		// Little-endian word + zero-padded to 32 hex chars (128-bit IPv4-in-IPv6)
		return fmt.Sprintf("%08X000000000000000000000000",
			uint32(b[3])<<24|uint32(b[2])<<16|uint32(b[1])<<8|uint32(b[0]))
	}
	// IPv6: not implemented here — return empty to trigger not-found.
	return ""
}
