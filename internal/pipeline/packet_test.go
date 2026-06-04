package pipeline

import (
	"encoding/binary"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
)

func TestParseIPv4UDPFlow(t *testing.T) {
	packet := make([]byte, 20+8)
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[12:16], []byte{198, 18, 0, 2})
	copy(packet[16:20], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(packet[20:22], 53000)
	binary.BigEndian.PutUint16(packet[22:24], 53)

	flow, err := ParseFlow(packet)
	if err != nil {
		t.Fatalf("parse flow: %v", err)
	}
	if flow.Transport != pidtrack.TransportUDP {
		t.Fatalf("expected udp, got %s", flow.Transport)
	}
	if flow.LocalIP != "198.18.0.2" || flow.RemoteIP != "8.8.8.8" {
		t.Fatalf("unexpected ips: %#v", flow)
	}
	if flow.LocalPort != 53000 || flow.RemotePort != 53 {
		t.Fatalf("unexpected ports: %#v", flow)
	}
}

func TestParseIPv6TCPFlow(t *testing.T) {
	packet := make([]byte, 40+20)
	packet[0] = 0x60
	packet[6] = 6
	copy(packet[8:24], []byte{0x20, 0x01, 0x0d, 0xb8})
	copy(packet[24:40], []byte{0x20, 0x01, 0x48, 0x60})
	binary.BigEndian.PutUint16(packet[40:42], 44321)
	binary.BigEndian.PutUint16(packet[42:44], 443)

	flow, err := ParseFlow(packet)
	if err != nil {
		t.Fatalf("parse flow: %v", err)
	}
	if flow.Transport != pidtrack.TransportTCP {
		t.Fatalf("expected tcp, got %s", flow.Transport)
	}
	if flow.LocalPort != 44321 || flow.RemotePort != 443 {
		t.Fatalf("unexpected ports: %#v", flow)
	}
}
