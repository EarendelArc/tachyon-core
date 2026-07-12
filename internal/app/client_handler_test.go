package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/pipeline"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestClientPacketHandlerSendsTGPDecision(t *testing.T) {
	sender := &fakeTGPPacketSender{}
	handler := clientPacketHandler{tgp: sender}
	packet := makeIPv4UDPPacket([]byte("hello"))

	err := handler.HandlePacket(context.Background(), pipeline.Decision{
		Action: pipeline.ActionTGP,
		Flow: pidtrack.FlowKey{
			Transport:  pidtrack.TransportUDP,
			RemoteIP:   "203.0.113.9",
			RemotePort: 27015,
		},
	}, packet)
	if err != nil {
		t.Fatalf("handle packet: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one packet, got %d", len(sender.sent))
	}
	if sender.streams[0] != capturedPacketStream {
		t.Fatalf("unexpected stream id: %d", sender.streams[0])
	}
	tunnel, err := tgp.ParseTunnelDatagram(sender.sent[0])
	if err != nil {
		t.Fatalf("parse tunnel datagram: %v", err)
	}
	if tunnel.LocalIP != netip.MustParseAddr("198.18.0.2") || tunnel.LocalPort != 53000 {
		t.Fatalf("unexpected tunnel local endpoint: %#v", tunnel)
	}
	if tunnel.RemoteIP != netip.MustParseAddr("203.0.113.9") || tunnel.RemotePort != 27015 {
		t.Fatalf("unexpected tunnel target: %#v", tunnel)
	}
	if !bytes.Equal(tunnel.Payload, []byte("hello")) {
		t.Fatalf("sent payload mismatch: %q", tunnel.Payload)
	}
}

func TestClientPacketHandlerSendsIPv6TGPDecision(t *testing.T) {
	sender := &fakeTGPPacketSender{}
	handler := clientPacketHandler{tgp: sender}
	packet := makeIPv6UDPPacket([]byte("hello-v6"))

	err := handler.HandlePacket(context.Background(), pipeline.Decision{
		Action: pipeline.ActionTGP,
		Flow: pidtrack.FlowKey{
			Transport:  pidtrack.TransportUDP,
			RemoteIP:   "2001:db8::9",
			RemotePort: 27015,
		},
	}, packet)
	if err != nil {
		t.Fatalf("handle packet: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one packet, got %d", len(sender.sent))
	}
	tunnel, err := tgp.ParseTunnelDatagram(sender.sent[0])
	if err != nil {
		t.Fatalf("parse tunnel datagram: %v", err)
	}
	if tunnel.LocalAddrPort() != netip.MustParseAddrPort("[2001:db8::2]:53000") {
		t.Fatalf("unexpected tunnel local endpoint: %s", tunnel.LocalAddrPort())
	}
	if tunnel.RemoteAddrPort() != netip.MustParseAddrPort("[2001:db8::9]:27015") {
		t.Fatalf("unexpected tunnel target: %s", tunnel.RemoteAddrPort())
	}
	if !bytes.Equal(tunnel.Payload, []byte("hello-v6")) {
		t.Fatalf("sent payload mismatch: %q", tunnel.Payload)
	}
}

func TestClientPacketHandlerDropsExplicitDropDecision(t *testing.T) {
	sender := &fakeTGPPacketSender{}
	handler := clientPacketHandler{tgp: sender}
	if err := handler.HandlePacket(context.Background(), pipeline.Decision{Action: pipeline.ActionDrop}, []byte{1}); err != nil {
		t.Fatalf("handle drop: %v", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("unexpected TGP sends: %d", len(sender.sent))
	}
}

func TestClientPacketHandlerRejectsCapturedDirectFailClosed(t *testing.T) {
	handler := clientPacketHandler{}
	err := handler.HandlePacket(context.Background(), pipeline.Decision{
		Action: pipeline.ActionDirect,
		Flow: pidtrack.FlowKey{
			RemoteIP:   "203.0.113.9",
			RemotePort: 443,
		},
	}, []byte{1})
	if !errors.Is(err, ErrDirectTrafficCaptured) {
		t.Fatalf("expected direct capture error, got %v", err)
	}
	var fatal *pipeline.FatalHandlerError
	if !errors.As(err, &fatal) {
		t.Fatalf("direct capture error must stop the pipeline, got %T", err)
	}
}

func TestClientPacketHandlerFailsFastWithoutTGPForwarder(t *testing.T) {
	handler := clientPacketHandler{}
	err := handler.HandlePacket(context.Background(), pipeline.Decision{Action: pipeline.ActionTGP}, makeIPv4UDPPacket(nil))
	if !errors.Is(err, ErrTGPForwarderUnavailable) {
		t.Fatalf("error = %v, want unavailable TGP forwarder", err)
	}
	var fatal *pipeline.FatalHandlerError
	if !errors.As(err, &fatal) {
		t.Fatalf("missing TGP forwarder must stop the pipeline, got %T", err)
	}
}

func TestClientPacketHandlerRejectsUnsupportedActionFailClosed(t *testing.T) {
	handler := clientPacketHandler{}
	err := handler.HandlePacket(context.Background(), pipeline.Decision{Action: pipeline.Action("proxy")}, []byte{1})
	if !errors.Is(err, ErrUnsupportedClientAction) {
		t.Fatalf("error = %v, want unsupported action", err)
	}
	var fatal *pipeline.FatalHandlerError
	if !errors.As(err, &fatal) {
		t.Fatalf("unsupported action must stop the pipeline, got %T", err)
	}
}

type fakeTGPPacketSender struct {
	streams []tgp.StreamID
	sent    [][]byte
}

func (s *fakeTGPPacketSender) SendPacket(_ context.Context, streamID tgp.StreamID, payload []byte) error {
	s.streams = append(s.streams, streamID)
	s.sent = append(s.sent, append([]byte(nil), payload...))
	return nil
}

func makeIPv4UDPPacket(payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[12:16], []byte{198, 18, 0, 2})
	copy(packet[16:20], []byte{203, 0, 113, 9})
	binary.BigEndian.PutUint16(packet[20:22], 53000)
	binary.BigEndian.PutUint16(packet[22:24], 27015)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func makeIPv6UDPPacket(payload []byte) []byte {
	packet := make([]byte, 40+8+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	packet[6] = 17
	packet[7] = 64
	src := netip.MustParseAddr("2001:db8::2").As16()
	dst := netip.MustParseAddr("2001:db8::9").As16()
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	binary.BigEndian.PutUint16(packet[40:42], 53000)
	binary.BigEndian.PutUint16(packet[42:44], 27015)
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(payload)))
	copy(packet[48:], payload)
	return packet
}
