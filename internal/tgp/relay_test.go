package tgp

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestRelayReceivesClientManagerPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	transport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}

	gotCh := make(chan RelayPacket, 1)
	relay, err := NewRelay(RelayOptions{
		Transport: transport,
		PacerPPS:  100000,
		Handler: RelayHandlerFunc(func(_ context.Context, packet RelayPacket) error {
			gotCh <- packet
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	defer relay.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.ListenAndServe(ctx)
	}()

	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr:       transport.LocalAddr().String(),
		LocalAddr:        "127.0.0.1:0",
		PacerPPS:         100000,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer manager.Close()

	payload := []byte("captured l3 packet")
	if err := manager.SendPacket(ctx, capturedPacketStreamID, payload); err != nil {
		t.Fatalf("manager send: %v", err)
	}

	select {
	case packet := <-gotCh:
		if !bytes.Equal(packet.Payload, payload) {
			t.Fatalf("relay got %q, want %q", packet.Payload, payload)
		}
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-ctx.Done():
		t.Fatalf("relay timeout: %v", ctx.Err())
	}
}
