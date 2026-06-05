package pidtrack

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// procNetFile selects the Linux socket table that matches the flow family.
func procNetFile(transport Transport, localIP string) string {
	proto := "tcp"
	if transport == TransportUDP {
		proto = "udp"
	}
	addr, err := netip.ParseAddr(localIP)
	if err == nil && addr.Is6() && !addr.Is4In6() {
		proto += "6"
	}
	return "/proc/net/" + proto
}

// ipToHex converts an IPv4 or IPv6 address to Linux /proc/net hex form.
func ipToHex(ip string, ipv6Table bool) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("parse ip %q: %w", ip, err)
	}
	if addr.Is4() || addr.Is4In6() {
		v4 := addr.As4()
		v4Hex := fmt.Sprintf("%02X%02X%02X%02X", v4[3], v4[2], v4[1], v4[0])
		if !ipv6Table {
			return v4Hex, nil
		}
		return "0000000000000000FFFF0000" + v4Hex, nil
	}
	v6 := addr.As16()
	if !ipv6Table {
		return "", fmt.Errorf("IPv6 address %s cannot be matched in IPv4 proc table", ip)
	}
	var b strings.Builder
	b.Grow(32)
	for i := 0; i < len(v6); i += 4 {
		fmt.Fprintf(&b, "%02X%02X%02X%02X", v6[i+3], v6[i+2], v6[i+1], v6[i])
	}
	return b.String(), nil
}

// findInodeInProcNet parses a Linux /proc/net socket table to find the socket
// inode for a given local IP and port.
func findInodeInProcNet(path, localIP string, localPort uint16) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	wantHex, err := ipToHex(localIP, strings.HasSuffix(path, "6"))
	if err != nil {
		return 0, err
	}
	wantPort := uint32(localPort)

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
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
