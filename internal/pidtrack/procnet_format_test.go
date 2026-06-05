package pidtrack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcNetFile(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		ip        string
		want      string
	}{
		{name: "tcp4", transport: TransportTCP, ip: "127.0.0.1", want: "/proc/net/tcp"},
		{name: "udp4", transport: TransportUDP, ip: "192.168.1.10", want: "/proc/net/udp"},
		{name: "tcp6", transport: TransportTCP, ip: "2001:db8::1", want: "/proc/net/tcp6"},
		{name: "udp6", transport: TransportUDP, ip: "::1", want: "/proc/net/udp6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := procNetFile(tt.transport, tt.ip); got != tt.want {
				t.Fatalf("procNetFile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIPToHex(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		ipv6Table bool
		want      string
	}{
		{name: "ipv4 table", ip: "127.0.0.1", want: "0100007F"},
		{name: "ipv4 mapped in ipv6 table", ip: "127.0.0.1", ipv6Table: true, want: "0000000000000000FFFF00000100007F"},
		{name: "ipv6 loopback", ip: "::1", ipv6Table: true, want: "00000000000000000000000001000000"},
		{name: "ipv6 documentation prefix", ip: "2001:db8::1", ipv6Table: true, want: "B80D0120000000000000000001000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipToHex(tt.ip, tt.ipv6Table)
			if err != nil {
				t.Fatalf("ipToHex() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ipToHex() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindInodeInProcNetIPv4Sample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:C001 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 424242 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	inode, err := findInodeInProcNet(path, "127.0.0.1", 49153)
	if err != nil {
		t.Fatalf("findInodeInProcNet() error = %v", err)
	}
	if inode != 424242 {
		t.Fatalf("inode = %d, want 424242", inode)
	}
}

func TestFindInodeInProcNetIPv6Sample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp6")
	content := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000001000000:C001 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 515151 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	inode, err := findInodeInProcNet(path, "::1", 49153)
	if err != nil {
		t.Fatalf("findInodeInProcNet() error = %v", err)
	}
	if inode != 515151 {
		t.Fatalf("inode = %d, want 515151", inode)
	}
}
