package app

import (
	"bytes"
	"context"
	"encoding/binary"
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

func TestClientPacketHandlerIgnoresNonTGPDecision(t *testing.T) {
	sender := &fakeTGPPacketSender{}
	handler := clientPacketHandler{tgp: sender}
	for _, action := range []pipeline.Action{pipeline.ActionDirect, pipeline.ActionDrop} {
		if err := handler.HandlePacket(context.Background(), pipeline.Decision{Action: action}, []byte{1}); err != nil {
			t.Fatalf("handle %s: %v", action, err)
		}
	}
	if len(sender.sent) != 0 {
		t.Fatalf("unexpected TGP sends: %d", len(sender.sent))
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
