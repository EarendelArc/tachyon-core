package tgp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
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

	payload, err := MarshalTunnelDatagram(TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("203.0.113.1"),
		RemotePort: 27015,
		Payload:    []byte("captured payload"),
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
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

func TestRelayMaxSessionsFailsClosedAndRecoversAfterIdleCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	gotCh := make(chan RelayPacket, 2)
	relay, err := NewRelay(RelayOptions{
		Transport:          transport,
		PacerPPS:           100000,
		MaxSessions:        1,
		SessionIdleTimeout: 150 * time.Millisecond,
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

	first := newTestClientManager(t, transport.LocalAddr().String(), time.Second)
	defer first.Close()
	if err := first.SendPacket(context.Background(), capturedPacketStreamID, mustTunnelPayload(t, "first")); err != nil {
		t.Fatalf("first send: %v", err)
	}
	select {
	case <-gotCh:
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-ctx.Done():
		t.Fatalf("timeout waiting for first packet: %v", ctx.Err())
	}

	second := newTestClientManager(t, transport.LocalAddr().String(), 150*time.Millisecond)
	defer second.Close()
	if err := second.SendPacket(context.Background(), capturedPacketStreamID, mustTunnelPayload(t, "second")); !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("expected second session handshake timeout, got %v", err)
	}

	time.Sleep(250 * time.Millisecond)
	third := newTestClientManager(t, transport.LocalAddr().String(), time.Second)
	defer third.Close()
	if err := third.SendPacket(context.Background(), capturedPacketStreamID, mustTunnelPayload(t, "third")); err != nil {
		t.Fatalf("third send after idle cleanup: %v", err)
	}
	select {
	case packet := <-gotCh:
		datagram, err := ParseTunnelDatagram(packet.Payload)
		if err != nil {
			t.Fatalf("parse third payload: %v", err)
		}
		if !bytes.Equal(datagram.Payload, []byte("third")) {
			t.Fatalf("unexpected third payload: %q", datagram.Payload)
		}
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-ctx.Done():
		t.Fatalf("timeout waiting for third packet: %v", ctx.Err())
	}
}

func TestRelayHandlerConcurrencyLimitDropsExcessPackets(t *testing.T) {
	block := make(chan struct{})
	relay, err := NewRelay(RelayOptions{
		ListenAddr:         "127.0.0.1:0",
		HandlerConcurrency: 1,
		Handler: RelayHandlerFunc(func(context.Context, RelayPacket) error {
			<-block
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	defer close(block)

	if !relay.dispatchPacket(context.Background(), RelayPacket{}) {
		t.Fatal("first handler dispatch should be accepted")
	}
	if relay.dispatchPacket(context.Background(), RelayPacket{}) {
		t.Fatal("second handler dispatch should be dropped at concurrency limit")
	}
}

func TestRelaySessionQueueDropsWhenFull(t *testing.T) {
	var id SessionID
	copy(id[:], []byte("queue-limit-test"))
	router := newRelayTransportRouter(nil, 1, 1)
	addr := mustRelayUDPAddr(t, "127.0.0.1:10001")
	sessionTransport, err := router.register(id, addr)
	if err != nil {
		t.Fatalf("register session: %v", err)
	}
	defer sessionTransport.Close()

	router.routeData(relayPacketEnvelope{packet: []byte("one"), from: addr})
	router.routeData(relayPacketEnvelope{packet: []byte("two"), from: addr})
	if got := router.droppedData.Load(); got != 1 {
		t.Fatalf("dropped data = %d, want 1", got)
	}
}

func TestRelayRoutesDataOnlyToMatchingSourceSession(t *testing.T) {
	var firstID SessionID
	copy(firstID[:], []byte("source-session-1"))
	var secondID SessionID
	copy(secondID[:], []byte("source-session-2"))
	router := newRelayTransportRouter(nil, 2, 1)
	firstAddr := mustRelayUDPAddr(t, "127.0.0.1:10011")
	secondAddr := mustRelayUDPAddr(t, "127.0.0.1:10012")
	first, err := router.register(firstID, firstAddr)
	if err != nil {
		t.Fatalf("register first session: %v", err)
	}
	defer first.Close()
	second, err := router.register(secondID, secondAddr)
	if err != nil {
		t.Fatalf("register second session: %v", err)
	}
	defer second.Close()

	router.routeData(relayPacketEnvelope{packet: []byte("for first"), from: firstAddr})

	assertNextPacket(t, first, "for first")
	assertNoPacket(t, second)
}

func TestRelayDropsUnknownSourceData(t *testing.T) {
	var firstID SessionID
	copy(firstID[:], []byte("unknown-drop-1!"))
	var secondID SessionID
	copy(secondID[:], []byte("unknown-drop-2!"))
	router := newRelayTransportRouter(nil, 2, 1)
	first, err := router.register(firstID, mustRelayUDPAddr(t, "127.0.0.1:10021"))
	if err != nil {
		t.Fatalf("register first session: %v", err)
	}
	defer first.Close()
	second, err := router.register(secondID, mustRelayUDPAddr(t, "127.0.0.1:10022"))
	if err != nil {
		t.Fatalf("register second session: %v", err)
	}
	defer second.Close()

	router.routeData(relayPacketEnvelope{packet: []byte("random noise"), from: mustRelayUDPAddr(t, "127.0.0.1:19999")})

	if got := router.droppedUnknownData.Load(); got != 1 {
		t.Fatalf("unknown source drops = %d, want 1", got)
	}
	assertNoPacket(t, first)
	assertNoPacket(t, second)
}

func TestRelayDropsDataFromMigratedUnknownAddressWithoutAffectingOriginal(t *testing.T) {
	var id SessionID
	copy(id[:], []byte("no-migration!!!!"))
	router := newRelayTransportRouter(nil, 2, 1)
	originalAddr := mustRelayUDPAddr(t, "127.0.0.1:10031")
	sessionTransport, err := router.register(id, originalAddr)
	if err != nil {
		t.Fatalf("register session: %v", err)
	}
	defer sessionTransport.Close()

	router.routeData(relayPacketEnvelope{packet: []byte("from new address"), from: mustRelayUDPAddr(t, "127.0.0.1:10032")})
	assertNoPacket(t, sessionTransport)

	router.routeData(relayPacketEnvelope{packet: []byte("from original"), from: originalAddr})
	assertNextPacket(t, sessionTransport, "from original")
}

func newTestClientManager(t *testing.T, remote string, timeout time.Duration) *ClientManager {
	t.Helper()
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr:       remote,
		LocalAddr:        "127.0.0.1:0",
		PacerPPS:         100000,
		HandshakeTimeout: timeout,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	return manager
}

func mustTunnelPayload(t *testing.T, payload string) []byte {
	t.Helper()
	wire, err := MarshalTunnelDatagram(TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("203.0.113.1"),
		RemotePort: 27015,
		Payload:    []byte(payload),
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
	return wire
}

func mustRelayUDPAddr(t *testing.T, raw string) net.Addr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		t.Fatalf("resolve UDP addr %q: %v", raw, err)
	}
	return addr
}

func assertNextPacket(t *testing.T, transport *relaySessionTransport, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, _, err := transport.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("read routed packet: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("routed packet = %q, want %q", got, want)
	}
}

func assertNoPacket(t *testing.T, transport *relaySessionTransport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if got, _, err := transport.ReadPacket(ctx); err == nil {
		t.Fatalf("unexpected routed packet: %q", got)
	}
}

func TestRelayReceivesConcurrentClientSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}

	gotCh := make(chan RelayPacket, 2)
	relay, err := NewRelay(RelayOptions{
		Transport:          transport,
		PacerPPS:           100000,
		SessionIdleTimeout: time.Second,
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

	payloads := [][]byte{[]byte("client-one"), []byte("client-two")}
	for idx, payload := range payloads {
		manager, err := NewClientManager(ClientManagerOptions{
			RemoteAddr:       transport.LocalAddr().String(),
			LocalAddr:        "127.0.0.1:0",
			PacerPPS:         100000,
			HandshakeTimeout: time.Second,
		})
		if err != nil {
			t.Fatalf("manager %d: %v", idx, err)
		}
		defer manager.Close()
		wire, err := MarshalTunnelDatagram(TunnelDatagram{
			LocalIP:    netip.MustParseAddr("198.18.0.2"),
			LocalPort:  uint16(53000 + idx),
			RemoteIP:   netip.MustParseAddr("203.0.113.1"),
			RemotePort: 27015,
			Payload:    payload,
		})
		if err != nil {
			t.Fatalf("marshal tunnel datagram %d: %v", idx, err)
		}
		if err := manager.SendPacket(ctx, capturedPacketStreamID, wire); err != nil {
			t.Fatalf("manager %d send: %v", idx, err)
		}
	}

	seenPayloads := map[string]struct{}{}
	seenSessions := map[SessionID]struct{}{}
	for len(seenPayloads) < len(payloads) {
		select {
		case packet := <-gotCh:
			datagram, err := ParseTunnelDatagram(packet.Payload)
			if err != nil {
				t.Fatalf("parse tunnel datagram: %v", err)
			}
			seenPayloads[string(datagram.Payload)] = struct{}{}
			seenSessions[packet.SessionID] = struct{}{}
		case err := <-errCh:
			t.Fatalf("relay exited early: %v", err)
		case <-ctx.Done():
			t.Fatalf("relay timeout: %v", ctx.Err())
		}
	}
	if len(seenSessions) != 2 {
		t.Fatalf("expected two relay sessions, got %d", len(seenSessions))
	}
}
