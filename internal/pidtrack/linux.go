//go:build linux

package pidtrack

import (
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
	procFile := procNetFile(flow.Transport, flow.LocalIP)

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
