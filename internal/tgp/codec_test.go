package tgp

import (
	"bytes"
	"errors"
	"testing"
)

func TestCodecSealOpenRoundTrip(t *testing.T) {
	var key [trafficKeySize]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	codec, err := NewCodec(key)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	sessionID, err := NewSessionID()
	if err != nil {
		t.Fatalf("session id: %v", err)
	}
	payload := []byte("game packet")
	header, err := NewDataHeader(sessionID, 7, 42, len(payload))
	if err != nil {
		t.Fatalf("header: %v", err)
	}

	wire, err := codec.Seal(42, header, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	packet, err := codec.Open(wire)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if packet.Inner.SessionID != sessionID {
		t.Fatal("session id mismatch")
	}
	if packet.Inner.StreamID != 7 || packet.Inner.PacketNumber != 42 {
		t.Fatalf("unexpected header: %#v", packet.Inner)
	}
	if !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("payload mismatch: %q", packet.Payload)
	}
}

func TestCodecRejectsTamperedPacket(t *testing.T) {
	var key [trafficKeySize]byte
	codec, err := NewCodec(key)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	header, err := NewDataHeader(SessionID{}, 1, 1, 3)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	wire, err := codec.Seal(1, header, []byte("abc"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	wire[len(wire)-1] ^= 0x80
	if _, err := codec.Open(wire); err == nil {
		t.Fatal("expected tampered packet to fail authentication")
	}
}

func TestCodecRejectsDatagramsAboveProtocolLimit(t *testing.T) {
	var key [trafficKeySize]byte
	codec, err := NewCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, maxTGPDataPayloadSize+1)
	header, err := NewDataHeader(SessionID{}, 1, 1, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Seal(1, header, payload); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversized seal error = %v, want %v", err, ErrDatagramTooLarge)
	}
	if _, err := codec.Open(make([]byte, MaxTGPDatagramSize+1)); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversized open error = %v, want %v", err, ErrDatagramTooLarge)
	}
}
