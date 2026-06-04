package tgp

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestHandshakeEstablishesEncryptedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}

	serverCh := make(chan *DatagramSession, 1)
	errCh := make(chan error, 1)
	go func() {
		session, err := AcceptSession(ctx, serverTransport, 100000)
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- session
	}()

	client, err := DialSession(ctx, "127.0.0.1:0", serverTransport.LocalAddr(), 100000)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	var server *DatagramSession
	select {
	case server = <-serverCh:
	case err := <-errCh:
		t.Fatalf("server accept: %v", err)
	case <-ctx.Done():
		t.Fatalf("server accept timeout: %v", ctx.Err())
	}
	defer server.Close()

	payload := []byte("post-handshake payload")
	if err := client.SendPacket(ctx, 3, payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket(ctx, 3)
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %q, want %q", got, payload)
	}
}
