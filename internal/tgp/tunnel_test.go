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

func TestTunnelDatagramV2RoundTripPreservesLeaseIdentity(t *testing.T) {
	original := TunnelDatagram{
		Identity: TunnelIdentity{
			FlowID:     testTunnelFlowID(1),
			Generation: 42,
			LeaseNonce: testTunnelLeaseNonce(2),
		},
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("203.0.113.10"),
		RemotePort: 27015,
		Payload:    []byte("lease-bound"),
	}
	wire, err := MarshalTunnelDatagram(original)
	if err != nil {
		t.Fatal(err)
	}
	if got := [4]byte(wire[:4]); got != tunnelMagicV2 {
		t.Fatalf("wire magic = %x, want v2", got)
	}
	parsed, err := ParseTunnelDatagram(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Identity != original.Identity || parsed.LocalAddrPort() != original.LocalAddrPort() ||
		parsed.RemoteAddrPort() != original.RemoteAddrPort() || !bytes.Equal(parsed.Payload, original.Payload) {
		t.Fatalf("v2 round trip mismatch: %#v != %#v", parsed, original)
	}
}

func TestTunnelDatagramRejectsIncompleteV2Identity(t *testing.T) {
	_, err := MarshalTunnelDatagram(TunnelDatagram{
		Identity: TunnelIdentity{FlowID: testTunnelFlowID(1)},
		LocalIP:  netip.MustParseAddr("198.18.0.2"), LocalPort: 53000,
		RemoteIP: netip.MustParseAddr("203.0.113.10"), RemotePort: 27015,
	})
	if err == nil {
		t.Fatal("incomplete v2 identity was accepted")
	}
}

func TestTunnelDatagramV2IdentityIsInsideAEADPayload(t *testing.T) {
	identity := TunnelIdentity{FlowID: testTunnelFlowID(3), Generation: 7, LeaseNonce: testTunnelLeaseNonce(4)}
	tunnelWire, err := MarshalTunnelDatagram(TunnelDatagram{
		Identity: identity,
		LocalIP:  netip.MustParseAddr("198.18.0.2"), LocalPort: 53000,
		RemoteIP: netip.MustParseAddr("203.0.113.10"), RemotePort: 27015,
		Payload: []byte("protected"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var key [trafficKeySize]byte
	key[0] = 1
	codec, err := NewCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	header, err := NewDataHeader(SessionID{}, capturedPacketStreamID, 1, len(tunnelWire))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := codec.Seal(1, header, tunnelWire)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := codec.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTunnelDatagram(opened.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Identity != identity {
		t.Fatalf("opened identity = %+v, want %+v", parsed.Identity, identity)
	}
	sealed[len(sealed)-1] ^= 0x01
	if _, err := codec.Open(sealed); err == nil {
		t.Fatal("tampered AEAD-protected tunnel identity was accepted")
	}
}

func TestDefaultTUNMTUFitsWorstCaseTGPDatagramInPublicPathMTU(t *testing.T) {
	const (
		publicPathMTU = 1400
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
	if outerPacketSize != 1396 {
		t.Fatalf("worst-case outer packet = %d bytes, want audited size 1396", outerPacketSize)
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

func testTunnelFlowID(value byte) FlowID {
	var id FlowID
	id[len(id)-1] = value
	return id
}

func testTunnelLeaseNonce(value byte) LeaseNonce {
	var nonce LeaseNonce
	nonce[len(nonce)-1] = value
	return nonce
}
