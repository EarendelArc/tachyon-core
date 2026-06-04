package app

import (
	"bytes"
	"context"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/pipeline"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestClientPacketHandlerSendsTGPDecision(t *testing.T) {
	sender := &fakeTGPPacketSender{}
	handler := clientPacketHandler{tgp: sender}
	packet := []byte{0x45, 0, 0, 28}

	err := handler.HandlePacket(context.Background(), pipeline.Decision{
		Action: pipeline.ActionTGP,
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
	if !bytes.Equal(sender.sent[0], packet) {
		t.Fatalf("sent packet mismatch: %x != %x", sender.sent[0], packet)
	}
}

func TestClientPacketHandlerIgnoresNonTGPDecision(t *testing.T) {
	sender := &fakeTGPPacketSender{}
	handler := clientPacketHandler{tgp: sender}
	for _, action := range []pipeline.Action{pipeline.ActionXray, pipeline.ActionDirect, pipeline.ActionDrop} {
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
