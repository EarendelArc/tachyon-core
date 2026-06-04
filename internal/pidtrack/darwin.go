//go:build darwin

package pidtrack

import (
	"context"
	"fmt"
)

// darwinProvider implements Provider using libproc.
//
// TODO M1: Implement using proc_pidinfo(PROC_PIDLISTFDS) + PROC_PIDFDSOCKETINFO.
// No root required — only works for processes owned by the current user.
type darwinProvider struct{}

func newProvider() (Provider, error) {
	return &darwinProvider{}, nil
}

func (p *darwinProvider) LookupByFlow(_ context.Context, flow FlowKey) (ProcessInfo, error) {
	// Stub: routing engine will fall back to GeoIP/domain rules.
	return ProcessInfo{}, fmt.Errorf("darwin pidtrack not yet implemented (flow: %s %s:%d)",
		flow.Transport, flow.LocalIP, flow.LocalPort)
}

func (p *darwinProvider) LookupPID(_ context.Context, pid int) (ProcessInfo, error) {
	return ProcessInfo{}, fmt.Errorf("darwin LookupPID not yet implemented (pid: %d)", pid)
}
