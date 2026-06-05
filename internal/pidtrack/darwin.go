//go:build darwin

package pidtrack

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// darwinProvider implements Provider using the macOS lsof/ps tools.
// This does not require CGO or root for current-user processes. A future
// production backend can replace this with libproc for lower overhead.
type darwinProvider struct {
	lsofPath string
	psPath   string
}

func newProvider() (Provider, error) {
	return &darwinProvider{
		lsofPath: "/usr/sbin/lsof",
		psPath:   "/bin/ps",
	}, nil
}

func (p *darwinProvider) LookupByFlow(ctx context.Context, flow FlowKey) (ProcessInfo, error) {
	if flow.LocalPort == 0 {
		return ProcessInfo{}, fmt.Errorf("invalid local port for flow: %d", flow.LocalPort)
	}

	networkArg := "-iTCP:" + strconv.Itoa(int(flow.LocalPort))
	if flow.Transport == TransportUDP {
		networkArg = "-iUDP:" + strconv.Itoa(int(flow.LocalPort))
	}

	output, err := exec.CommandContext(ctx, p.lsofPath, "-nP", "-Fpcn", networkArg).Output()
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("lsof %s: %w", networkArg, err)
	}
	records, err := parseLsofFieldOutput(string(output))
	if err != nil {
		return ProcessInfo{}, err
	}
	for _, record := range records {
		if !lsofRecordMatchesFlow(record, flow) {
			continue
		}
		info, err := p.LookupPID(ctx, record.PID)
		if err == nil {
			return info, nil
		}
		return ProcessInfo{
			PID:  record.PID,
			Name: record.Name,
		}, nil
	}
	return ProcessInfo{}, fmt.Errorf("socket %s %s:%d not found", flow.Transport, flow.LocalIP, flow.LocalPort)
}

func (p *darwinProvider) LookupPID(ctx context.Context, pid int) (ProcessInfo, error) {
	if pid <= 0 {
		return ProcessInfo{}, fmt.Errorf("invalid pid: %d", pid)
	}
	output, err := exec.CommandContext(
		ctx,
		p.psPath,
		"-p", strconv.Itoa(pid),
		"-o", "pid=",
		"-o", "ppid=",
		"-o", "comm=",
	).Output()
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("ps pid %d: %w", pid, err)
	}
	line := strings.TrimSpace(string(output))
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return ProcessInfo{}, fmt.Errorf("unexpected ps output for pid %d: %q", pid, line)
	}
	parsedPID, err := strconv.Atoi(fields[0])
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("parse ps pid %q: %w", fields[0], err)
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("parse ps ppid %q: %w", fields[1], err)
	}
	exePath := strings.Join(fields[2:], " ")
	return ProcessInfo{
		PID:            parsedPID,
		ParentPID:      ppid,
		Name:           filepath.Base(exePath),
		ExecutablePath: exePath,
	}, nil
}
