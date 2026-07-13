package tgp

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/tun"
)

func TestTunnelDatagramRoundTripIPv4(t *testing.T) {
	original := TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
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
	if got.LocalIP != original.LocalIP || got.LocalPort != original.LocalPort ||
		got.RemoteIP != original.RemoteIP || got.RemotePort != original.RemotePort ||
		!bytes.Equal(got.Payload, original.Payload) {
		t.Fatalf("round trip mismatch: %#v != %#v", got, original)
	}
}

func TestTunnelDatagramRoundTripIPv6(t *testing.T) {
	original := TunnelDatagram{
		LocalIP:    netip.MustParseAddr("2001:db8::2"),
		LocalPort:  53000,
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
	if got.LocalIP != original.LocalIP || got.LocalPort != original.LocalPort ||
		got.RemoteIP != original.RemoteIP || got.RemotePort != original.RemotePort ||
		!bytes.Equal(got.Payload, original.Payload) {
		t.Fatalf("round trip mismatch: %#v != %#v", got, original)
	}
}

func TestDefaultTUNMTUFitsWorstCaseTGPDatagramInPublicPathMTU(t *testing.T) {
	const (
		publicPathMTU = 1500
		ipv6Header    = 40
		udpHeader     = 8
	)
	innerUDPPayload := make([]byte, tun.DefaultMTU-ipv6Header-udpHeader)
	tunnelWire, err := MarshalTunnelDatagram(TunnelDatagram{
		LocalIP:    netip.MustParseAddr("2001:db8::2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("2001:db8::1"),
		RemotePort: 27015,
		Payload:    innerUDPPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	fecWire, err := frameFECData(tunnelWire, len(tunnelWire)+fecLengthPrefixSize)
	if err != nil {
		t.Fatal(err)
	}
	var key [trafficKeySize]byte
	codec, err := NewCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	var sessionID SessionID
	header, err := NewDataHeader(sessionID, capturedPacketStreamID, 1, len(fecWire))
	if err != nil {
		t.Fatal(err)
	}
	tgpWire, err := codec.Seal(1, header, fecWire)
	if err != nil {
		t.Fatal(err)
	}
	outerPacketSize := ipv6Header + udpHeader + len(tgpWire)
	if outerPacketSize > publicPathMTU {
		t.Fatalf("worst-case outer packet = %d bytes, exceeds public path MTU %d", outerPacketSize, publicPathMTU)
	}
	if outerPacketSize != 1496 {
		t.Fatalf("worst-case outer packet = %d bytes, want audited size 1496", outerPacketSize)
	}
}

func TestLowPMTUBudgetProducesBoundedOuterPacket(t *testing.T) {
	const (
		lowPathMTU = 1280
		ipv6Header = 40
		udpHeader  = 8
	)
	tunMTU := MinTGPDatagramSize - WorstCaseTUNOverhead
	innerUDPPayload := make([]byte, tunMTU-ipv6Header-udpHeader)
	tunnelWire, err := MarshalTunnelDatagram(TunnelDatagram{
		LocalIP:    netip.MustParseAddr("2001:db8::2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("2001:db8::1"),
		RemotePort: 27015,
		Payload:    innerUDPPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	fecWire, err := frameFECData(tunnelWire, len(tunnelWire)+fecLengthPrefixSize)
	if err != nil {
		t.Fatal(err)
	}
	var key [trafficKeySize]byte
	codec, err := NewCodecWithMaxDatagramSize(key, MinTGPDatagramSize)
	if err != nil {
		t.Fatal(err)
	}
	header, err := NewDataHeader(SessionID{}, capturedPacketStreamID, 1, len(fecWire))
	if err != nil {
		t.Fatal(err)
	}
	tgpWire, err := codec.Seal(1, header, fecWire)
	if err != nil {
		t.Fatal(err)
	}
	outerPacketSize := ipv6Header + udpHeader + len(tgpWire)
	if outerPacketSize != lowPathMTU {
		t.Fatalf("low-PMTU outer packet = %d, want %d", outerPacketSize, lowPathMTU)
	}
}
