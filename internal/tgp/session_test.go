package tgp

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestDatagramSessionLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, server, err := NewLoopbackSessionPair(ctx, 100000)
	if err != nil {
		t.Fatalf("session pair: %v", err)
	}
	defer client.Close()
	defer server.Close()

	payload := []byte("client input frame")
	if err := client.SendPacket(ctx, 7, payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket(ctx, 7)
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %q, want %q", got, payload)
	}

	reply := []byte("server relay frame")
	if err := server.SendPacket(ctx, 7, reply); err != nil {
		t.Fatalf("server send: %v", err)
	}
	got, err = client.RecvPacket(ctx, 7)
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("client got %q, want %q", got, reply)
	}

	if stats := client.Stats(); stats.BytesSent != uint64(len(payload)) || stats.BytesReceived != uint64(len(reply)) {
		t.Fatalf("unexpected client stats: %#v", stats)
	}
}

func TestDatagramSessionRecvHonorsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, server, err := NewLoopbackSessionPair(ctx, 100000)
	if err != nil {
		t.Fatalf("session pair: %v", err)
	}
	defer client.Close()
	defer server.Close()

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer shortCancel()
	if _, err := client.RecvPacket(shortCtx, 99); err == nil {
		t.Fatal("expected recv timeout")
	}
}
