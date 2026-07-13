package tgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestHandshakeNegotiatesMinimumAuthenticatedDatagramBudget(t *testing.T) {
	tests := []struct {
		name      string
		clientMax int
		serverMax int
		effective int
	}{
		{name: "client lower", clientMax: MinTGPDatagramSize, serverMax: MaxTGPDatagramSize, effective: MinTGPDatagramSize},
		{name: "server lower", clientMax: MaxTGPDatagramSize, serverMax: DefaultTGPDatagramSize, effective: DefaultTGPDatagramSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			serverTransport, err := ListenUDP("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			authKey := []byte("authenticated-budget-test-key")
			serverCh := make(chan *DatagramSession, 1)
			errCh := make(chan error, 1)
			go func() {
				session, acceptErr := AcceptSessionWithOptions(ctx, serverTransport, SessionRuntimeOptions{
					PacerPPS: 100000, MaxDatagramSize: tt.serverMax, AuthKey: authKey,
				})
				if acceptErr != nil {
					errCh <- acceptErr
					return
				}
				serverCh <- session
			}()

			client, err := DialSessionWithOptions(ctx, "127.0.0.1:0", serverTransport.LocalAddr(), SessionRuntimeOptions{
				PacerPPS: 100000, MaxDatagramSize: tt.clientMax, AuthKey: authKey,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var server *DatagramSession
			select {
			case server = <-serverCh:
			case err := <-errCh:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer server.Close()
			for name, session := range map[string]*DatagramSession{"client": client, "server": server} {
				if session.sendCodec.maxDatagramSize != tt.effective || session.recvCodec.maxDatagramSize != tt.effective {
					t.Fatalf("%s effective datagram budget = send %d recv %d, want %d", name, session.sendCodec.maxDatagramSize, session.recvCodec.maxDatagramSize, tt.effective)
				}
			}
		})
	}
}

func TestHandshakeAuthenticatesDatagramBudget(t *testing.T) {
	var sessionID SessionID
	var publicKey PublicKey
	authKey := []byte("authenticated-budget-test-key")
	wire, err := marshalHandshake(handshakeHello, sessionID, publicKey, DefaultTGPDatagramSize, 0, authKey, PublicKey{})
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(wire[outerHeaderSize+53:outerHeaderSize+55], uint16(MinTGPDatagramSize))
	msg, err := parseHandshake(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHandshakeAuth(msg, authKey, PublicKey{}); !errors.Is(err, ErrInvalidHandshake) {
		t.Fatalf("tampered datagram budget auth error = %v, want %v", err, ErrInvalidHandshake)
	}
}

func TestHandshakeAuthenticatesRelayClock(t *testing.T) {
	var sessionID SessionID
	var publicKey PublicKey
	authKey := []byte("authenticated-relay-clock-key")
	wire, err := marshalHandshake(handshakeHelloAck, sessionID, publicKey, DefaultTGPDatagramSize, time.Now().UnixMilli(), authKey, PublicKey{})
	if err != nil {
		t.Fatal(err)
	}
	wire[outerHeaderSize+55] ^= 0x01
	msg, err := parseHandshake(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHandshakeAuth(msg, authKey, PublicKey{}); !errors.Is(err, ErrInvalidHandshake) {
		t.Fatalf("tampered relay clock auth error = %v, want %v", err, ErrInvalidHandshake)
	}
}

func TestEstimateRelayClockOffsetCorrectsClientSkew(t *testing.T) {
	relayMidpoint := time.UnixMilli(1_700_000_000_000)
	for _, skew := range []time.Duration{-2 * time.Second, 2 * time.Second} {
		t.Run(skew.String(), func(t *testing.T) {
			helloSentAt := relayMidpoint.Add(-50 * time.Millisecond).Add(skew)
			ackReceivedAt := relayMidpoint.Add(50 * time.Millisecond).Add(skew)
			offset, err := estimateRelayClockOffset(helloSentAt, ackReceivedAt, relayMidpoint.UnixMilli())
			if err != nil {
				t.Fatal(err)
			}
			wantOffset := -skew - 50*time.Millisecond
			if offset != wantOffset {
				t.Fatalf("clock offset = %s, want %s", offset, wantOffset)
			}
			if aligned := ackReceivedAt.Add(offset); !aligned.Equal(relayMidpoint) {
				t.Fatalf("aligned client time = %s", aligned)
			}
		})
	}
}

func TestHandshakeRejectsOlderPeers(t *testing.T) {
	for _, version := range []struct {
		value    byte
		bodySize int
	}{{value: 1, bodySize: 4 + 1 + 16 + publicKeySize}, {value: 2, bodySize: 4 + 1 + 16 + publicKeySize + 2}} {
		body := make([]byte, version.bodySize)
		copy(body[:4], []byte{'T', 'G', 'H', version.value})
		body[4] = byte(handshakeHello)
		outer, err := NewOuterHeader(handshakeSequence, len(body))
		if err != nil {
			t.Fatal(err)
		}
		wire := append(marshalOuterHeader(outer), body...)
		if _, err := parseHandshake(wire); !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("version-%d handshake error = %v, want %v", version.value, err, ErrInvalidHandshake)
		}
	}
}

func TestHandshakeRejectsAuthenticatedAckForwardedFromUnknownSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	transport := newMigrationTestTransport()
	expected := mustUDPAddr(t, "127.0.0.1:32300")
	unknown := mustUDPAddr(t, "127.0.0.1:32301")
	authKey := []byte("authenticated-ack-source-key")
	type dialResult struct {
		session *DatagramSession
		err     error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		session, err := dialSessionWithTransport(ctx, transport, expected, SessionRuntimeOptions{
			PacerPPS: 100000, AuthKey: authKey,
		})
		resultCh <- dialResult{session: session, err: err}
	}()

	helloWire := transport.nextWritePacket(ctx)
	if got := transport.nextWriteAddr(ctx); !sameAddr(got, expected) {
		t.Fatalf("hello destination = %v, want %v", got, expected)
	}
	hello := mustParseHandshake(t, helloWire)
	serverKeys, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ack, err := marshalHandshake(handshakeHelloAck, hello.sessionID, serverKeys.PublicKey(), hello.maxDatagramSize, time.Now().UnixMilli(), authKey, hello.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(ack, unknown)
	select {
	case result := <-resultCh:
		if result.session != nil {
			_ = result.session.Close()
		}
		t.Fatalf("forwarded ack completed handshake: %v", result.err)
	case <-time.After(30 * time.Millisecond):
	}

	transport.inject(ack, expected)
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatal(result.err)
		}
		defer result.session.Close()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func mustParseHandshake(t *testing.T, wire []byte) handshakeMessage {
	t.Helper()
	msg, err := parseHandshake(wire)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

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
