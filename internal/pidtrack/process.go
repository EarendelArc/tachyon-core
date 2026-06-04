package pidtrack

import "context"

type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

type FlowKey struct {
	Transport  Transport
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
}

type ProcessSummary struct {
	PID            int
	Name           string
	ExecutablePath string
}

type ProcessInfo struct {
	PID            int
	ParentPID      int
	Name           string
	ExecutablePath string
	SHA256         string
	CommandLine    []string
	Ancestors      []ProcessSummary
	Tags           map[string]string
}

type Provider interface {
	LookupByFlow(ctx context.Context, flow FlowKey) (ProcessInfo, error)
	LookupPID(ctx context.Context, pid int) (ProcessInfo, error)
}
