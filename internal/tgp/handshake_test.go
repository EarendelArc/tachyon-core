package tgp

import (
	"bytes"
	"context"
	"errors"
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

func TestHandshakeWithPSKEstablishesEncryptedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}

	authKey := []byte("0123456789abcdef0123456789abcdef")
	serverCh := make(chan *DatagramSession, 1)
	errCh := make(chan error, 1)
	go func() {
		session, err := AcceptSessionWithOptions(ctx, serverTransport, SessionRuntimeOptions{
			PacerPPS: 100000,
			AuthKey:  authKey,
		})
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- session
	}()

	client, err := DialSessionWithOptions(ctx, "127.0.0.1:0", serverTransport.LocalAddr(), SessionRuntimeOptions{
		PacerPPS: 100000,
		AuthKey:  authKey,
	})
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

	payload := []byte("psk-authenticated payload")
	if err := client.SendPacket(ctx, 5, payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket(ctx, 5)
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %q, want %q", got, payload)
	}
}

func TestHandshakeRejectsMismatchedPSK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverTransport.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := AcceptSessionWithOptions(ctx, serverTransport, SessionRuntimeOptions{
			PacerPPS: 100000,
			AuthKey:  []byte("server-auth-key-0123456789"),
		})
		serverErr <- err
	}()

	client, err := DialSessionWithOptions(ctx, "127.0.0.1:0", serverTransport.LocalAddr(), SessionRuntimeOptions{
		PacerPPS: 100000,
		AuthKey:  []byte("client-auth-key-0123456789"),
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("expected mismatched PSK handshake to fail")
	}
	if !errors.Is(err, ErrHandshakeTimeout) || (!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled)) {
		t.Fatalf("expected handshake timeout for rejected handshake, got %v", err)
	}

	select {
	case err := <-serverErr:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("expected server context timeout, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server accept did not return after context timeout")
	}
}

func TestHandshakeRejectsClientPSKWhenServerHasNoPSK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverTransport.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := AcceptSessionWithOptions(ctx, serverTransport, SessionRuntimeOptions{PacerPPS: 100000})
		serverErr <- err
	}()

	client, err := DialSessionWithOptions(ctx, "127.0.0.1:0", serverTransport.LocalAddr(), SessionRuntimeOptions{
		PacerPPS: 100000,
		AuthKey:  []byte("client-auth-key-0123456789"),
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("expected authenticated client to fail against unauthenticated server")
	}
	if !errors.Is(err, ErrHandshakeTimeout) || (!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled)) {
		t.Fatalf("expected handshake timeout for rejected handshake, got %v", err)
	}

	select {
	case err := <-serverErr:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("expected server context timeout, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server accept did not return after context timeout")
	}
}

func TestHandshakeRejectsUnauthenticatedClientWhenServerRequiresPSK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverTransport.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := AcceptSessionWithOptions(ctx, serverTransport, SessionRuntimeOptions{
			PacerPPS: 100000,
			AuthKey:  []byte("server-auth-key-0123456789"),
		})
		serverErr <- err
	}()

	client, err := DialSessionWithOptions(ctx, "127.0.0.1:0", serverTransport.LocalAddr(), SessionRuntimeOptions{PacerPPS: 100000})
	if err == nil {
		_ = client.Close()
		t.Fatal("expected unauthenticated client to fail against authenticated server")
	}
	if !errors.Is(err, ErrHandshakeTimeout) || (!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled)) {
		t.Fatalf("expected handshake timeout for rejected handshake, got %v", err)
	}

	select {
	case err := <-serverErr:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("expected server context timeout, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server accept did not return after context timeout")
	}
}

func TestHandshakeTimesOutWhenAckIsDropped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	blackhole, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole: %v", err)
	}
	defer blackhole.Close()

	client, err := DialSessionWithOptions(ctx, "127.0.0.1:0", blackhole.LocalAddr(), SessionRuntimeOptions{PacerPPS: 100000})
	if err == nil {
		_ = client.Close()
		t.Fatal("expected dropped ack handshake to fail")
	}
	if !errors.Is(err, ErrHandshakeTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected handshake timeout with context deadline, got %v", err)
	}
}

func TestMultipathHandshakeEstablishesEncryptedSession(t *testing.T) {
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

	client, err := DialSessionMultipathWithOptions(
		ctx,
		[]string{"127.0.0.1:0", "127.0.0.1:0"},
		serverTransport.LocalAddr(),
		SessionRuntimeOptions{PacerPPS: 100000},
	)
	if err != nil {
		t.Fatalf("client multipath dial: %v", err)
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

	payload := []byte("multipath handshake payload")
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
}
