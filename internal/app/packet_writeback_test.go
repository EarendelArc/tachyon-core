package app

import (
	"net/netip"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/pipeline"
)

func TestBuildIPv4UDPPacket(t *testing.T) {
	packet, err := buildIPv4UDPPacket(
		netip.MustParseAddrPort("203.0.113.9:27015"),
		netip.MustParseAddrPort("198.18.0.2:53000"),
		[]byte("reply"),
	)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	flow, payload, err := pipeline.ExtractUDPPayload(packet)
	if err != nil {
		t.Fatalf("extract payload: %v", err)
	}
	if flow.LocalIP != "203.0.113.9" || flow.LocalPort != 27015 {
		t.Fatalf("unexpected source flow: %#v", flow)
	}
	if flow.RemoteIP != "198.18.0.2" || flow.RemotePort != 53000 {
		t.Fatalf("unexpected destination flow: %#v", flow)
	}
	if string(payload) != "reply" {
		t.Fatalf("unexpected payload: %q", payload)
	}
}
