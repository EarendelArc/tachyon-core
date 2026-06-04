package tgp

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestTunnelDatagramRoundTripIPv4(t *testing.T) {
	original := TunnelDatagram{
		RemoteIP:   netip.MustParseAddr("203.0.113.10"),
		RemotePort: 27015,
		Payload:    []byte("game"),
	}
	wire, err := MarshalTunnelDatagram(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseTunnelDatagram(wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.RemoteIP != original.RemoteIP || got.RemotePort != original.RemotePort || !bytes.Equal(got.Payload, original.Payload) {
		t.Fatalf("round trip mismatch: %#v != %#v", got, original)
	}
}

func TestTunnelDatagramRoundTripIPv6(t *testing.T) {
	original := TunnelDatagram{
		RemoteIP:   netip.MustParseAddr("2001:db8::1"),
		RemotePort: 443,
		Payload:    []byte("voice"),
	}
	wire, err := MarshalTunnelDatagram(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseTunnelDatagram(wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.RemoteIP != original.RemoteIP || got.RemotePort != original.RemotePort || !bytes.Equal(got.Payload, original.Payload) {
		t.Fatalf("round trip mismatch: %#v != %#v", got, original)
	}
}
