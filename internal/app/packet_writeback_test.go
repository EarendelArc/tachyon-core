package app

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/pipeline"
)

func TestBuildUDPPacketIPv4AndIPv6(t *testing.T) {
	tests := []struct {
		name string
		src  netip.AddrPort
		dst  netip.AddrPort
	}{
		{
			name: "IPv4",
			src:  netip.MustParseAddrPort("203.0.113.9:27015"),
			dst:  netip.MustParseAddrPort("198.18.0.2:53000"),
		},
		{
			name: "IPv6",
			src:  netip.MustParseAddrPort("[2001:db8::9]:27015"),
			dst:  netip.MustParseAddrPort("[2001:db8::2]:53000"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := buildUDPPacket(tt.src, tt.dst, []byte("reply"))
			if err != nil {
				t.Fatalf("build packet: %v", err)
			}
			flow, payload, err := pipeline.ExtractUDPPayload(packet)
			if err != nil {
				t.Fatalf("extract payload: %v", err)
			}
			if flow.LocalIP != tt.src.Addr().String() || flow.LocalPort != tt.src.Port() {
				t.Fatalf("unexpected source flow: %#v", flow)
			}
			if flow.RemoteIP != tt.dst.Addr().String() || flow.RemotePort != tt.dst.Port() {
				t.Fatalf("unexpected destination flow: %#v", flow)
			}
			if string(payload) != "reply" {
				t.Fatalf("unexpected payload: %q", payload)
			}
			assertUDPWritebackChecksums(t, packet, tt.src.Addr(), tt.dst.Addr())
		})
	}
}

func TestBuildUDPPacketRejectsMixedAddressFamilies(t *testing.T) {
	_, err := buildUDPPacket(
		netip.MustParseAddrPort("203.0.113.9:27015"),
		netip.MustParseAddrPort("[2001:db8::2]:53000"),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "address families differ") {
		t.Fatalf("error = %v, want address-family mismatch", err)
	}
}

func assertUDPWritebackChecksums(t *testing.T, packet []byte, src netip.Addr, dst netip.Addr) {
	t.Helper()
	switch packet[0] >> 4 {
	case 4:
		if internetChecksum(packet[:20]) != 0 {
			t.Fatal("invalid IPv4 header checksum")
		}
		udp := packet[20:]
		if binary.BigEndian.Uint16(udp[6:8]) == 0 || udpChecksumIPv4(src, dst, udp) != 0 {
			t.Fatal("invalid IPv4 UDP checksum")
		}
	case 6:
		udp := packet[40:]
		if binary.BigEndian.Uint16(udp[6:8]) == 0 || udpChecksumIPv6(src, dst, udp) != 0 {
			t.Fatal("invalid IPv6 UDP checksum")
		}
	default:
		t.Fatalf("unexpected IP version %d", packet[0]>>4)
	}
}
