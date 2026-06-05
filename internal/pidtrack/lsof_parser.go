package pidtrack

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type lsofRecord struct {
	PID   int
	Name  string
	Names []string
}

func parseLsofFieldOutput(output string) ([]lsofRecord, error) {
	var records []lsofRecord
	var current *lsofRecord

	flush := func() {
		if current != nil && current.PID > 0 {
			records = append(records, *current)
		}
		current = nil
	}

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if line == "" {
			continue
		}
		field := line[0]
		value := line[1:]
		switch field {
		case 'p':
			flush()
			pid, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse lsof pid %q: %w", value, err)
			}
			current = &lsofRecord{PID: pid}
		case 'c':
			if current != nil {
				current.Name = value
			}
		case 'n':
			if current != nil {
				current.Names = append(current.Names, value)
			}
		}
	}
	flush()
	return records, nil
}

func lsofRecordMatchesFlow(record lsofRecord, flow FlowKey) bool {
	for _, name := range record.Names {
		if lsofNameMatchesFlow(name, flow) {
			return true
		}
	}
	return false
}

func lsofNameMatchesFlow(name string, flow FlowKey) bool {
	value := normalizeLsofEndpointName(name)
	local, remote, hasRemote := strings.Cut(value, "->")
	if !endpointMatches(local, flow.LocalIP, flow.LocalPort) {
		return false
	}
	if !hasRemote || flow.RemotePort == 0 {
		return true
	}
	return endpointMatches(remote, flow.RemoteIP, flow.RemotePort)
}

func normalizeLsofEndpointName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "TCP ")
	value = strings.TrimPrefix(value, "UDP ")
	if idx := strings.Index(value, " ("); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func endpointMatches(endpoint, ip string, port uint16) bool {
	host, endpointPort, ok := splitEndpoint(endpoint)
	if !ok || endpointPort != port {
		return false
	}
	return hostMatches(host, ip)
}

func splitEndpoint(endpoint string) (string, uint16, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", 0, false
	}

	if strings.HasPrefix(endpoint, "[") {
		closeAt := strings.LastIndex(endpoint, "]:")
		if closeAt < 0 {
			return "", 0, false
		}
		port, ok := parseLsofPort(endpoint[closeAt+2:])
		return endpoint[1:closeAt], port, ok
	}

	colonAt := strings.LastIndex(endpoint, ":")
	if colonAt < 0 {
		return "", 0, false
	}
	port, ok := parseLsofPort(endpoint[colonAt+1:])
	if !ok {
		return "", 0, false
	}
	return strings.Trim(endpoint[:colonAt], "[]"), port, true
}

func parseLsofPort(value string) (uint16, bool) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(port), true
}

func hostMatches(host, ip string) bool {
	host = strings.TrimSpace(host)
	ip = strings.TrimSpace(ip)
	if host == "" || host == "*" || host == "0.0.0.0" || host == "::" {
		return true
	}
	if strings.EqualFold(host, ip) {
		return true
	}
	hostAddr, hostErr := netip.ParseAddr(host)
	ipAddr, ipErr := netip.ParseAddr(ip)
	return hostErr == nil && ipErr == nil && hostAddr == ipAddr
}
