package tgp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

func TestRelayAuthenticatesAdditionalPathWithOneTimeChallenge(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 4, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("path-admission!!!"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 91
	original := mustRelayUDPAddr(t, "127.0.0.1:10101")
	additional := mustRelayUDPAddr(t, "127.0.0.1:10102")
	session, err := router.registerWithPathAuth(sessionID, original, pathKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	clientNonce := [pathControlNonceSize]byte{1, 3, 3, 7}
	request, err := marshalPathControl(pathControlRequest, sessionID, clientNonce, [pathControlNonceSize]byte{}, pathKey)
	if err != nil {
		t.Fatal(err)
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: request, from: additional}, mustParsePathControl(t, request))
	challengeWrite := transport.nextWrite(t)
	if !sameAddr(challengeWrite.addr, additional) {
		t.Fatalf("challenge sent to %v, want %v", challengeWrite.addr, additional)
	}
	challenge := mustParsePathControl(t, challengeWrite.packet)
	response, err := marshalPathControl(pathControlResponse, sessionID, challenge.clientNonce, challenge.serverNonce, pathKey)
	if err != nil {
		t.Fatal(err)
	}

	wrongSource := mustRelayUDPAddr(t, "127.0.0.1:10103")
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: response, from: wrongSource}, mustParsePathControl(t, response))
	if session.IsSourceAuthorized(wrongSource) {
		t.Fatal("challenge response was accepted from a different source")
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: response, from: additional}, mustParsePathControl(t, response))
	if !session.IsSourceAuthorized(additional) {
		t.Fatal("valid additional path was not registered")
	}

	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: response, from: additional}, mustParsePathControl(t, response))
	if got := router.droppedPathControl.Load(); got < 2 {
		t.Fatalf("wrong-source and replayed responses were not rejected: drops=%d", got)
	}
	router.routeData(relayPacketEnvelope{packet: []byte("authenticated path"), from: additional})
	assertNextPacket(t, session, "authenticated path")
}

func TestRelayRejectsInvalidPathKeyAndSourceHijack(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 2, 1)
	var firstID SessionID
	copy(firstID[:], []byte("first-auth-path!"))
	var secondID SessionID
	copy(secondID[:], []byte("second-auth-path"))
	var firstKey [trafficKeySize]byte
	firstKey[0] = 11
	var secondKey [trafficKeySize]byte
	secondKey[0] = 22
	firstAddr := mustRelayUDPAddr(t, "127.0.0.1:10201")
	secondAddr := mustRelayUDPAddr(t, "127.0.0.1:10202")
	first, err := router.registerWithPathAuth(firstID, firstAddr, firstKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := router.registerWithPathAuth(secondID, secondAddr, secondKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	nonce := [pathControlNonceSize]byte{4, 2}
	wrongKeyRequest, err := marshalPathControl(pathControlRequest, firstID, nonce, [pathControlNonceSize]byte{}, secondKey)
	if err != nil {
		t.Fatal(err)
	}
	unknown := mustRelayUDPAddr(t, "127.0.0.1:10203")
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: wrongKeyRequest, from: unknown}, mustParsePathControl(t, wrongKeyRequest))
	transport.assertNoWrite(t)
	if first.IsSourceAuthorized(unknown) {
		t.Fatal("source with an invalid path key was registered")
	}

	hijackRequest, err := marshalPathControl(pathControlRequest, firstID, nonce, [pathControlNonceSize]byte{}, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: hijackRequest, from: secondAddr}, mustParsePathControl(t, hijackRequest))
	transport.assertNoWrite(t)
	if !second.IsSourceAuthorized(secondAddr) || first.IsSourceAuthorized(secondAddr) {
		t.Fatal("an existing source mapping was stolen by another CID")
	}
}

func TestRelayPathRequestReplayCannotSaturateGlobalChallengeState(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 2, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("stateless-path-id"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 29
	original := mustRelayUDPAddr(t, "127.0.0.1:10701")
	session, err := router.registerWithPathAuth(sessionID, original, pathKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	nonce := [pathControlNonceSize]byte{7, 7, 7, 7}
	request, err := marshalPathControl(pathControlRequest, sessionID, nonce, [pathControlNonceSize]byte{}, pathKey)
	if err != nil {
		t.Fatal(err)
	}
	const replayCount = 5000
	for port := 0; port < replayCount; port++ {
		source := mustRelayUDPAddr(t, fmt.Sprintf("127.0.0.1:%d", 12000+port))
		router.handlePathControl(context.Background(), relayPacketEnvelope{packet: request, from: source}, mustParsePathControl(t, request))
	}
	if got := len(transport.writes); got != replayCount {
		t.Fatalf("stateless challenges = %d, want %d; request replay exhausted shared state", got, replayCount)
	}
	firstSource := mustRelayUDPAddr(t, "127.0.0.1:12000")
	challenge := mustParsePathControl(t, transport.nextWrite(t).packet)
	response, err := marshalPathControl(pathControlResponse, sessionID, challenge.clientNonce, challenge.serverNonce, pathKey)
	if err != nil {
		t.Fatal(err)
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: response, from: firstSource}, mustParsePathControl(t, response))
	if !session.IsSourceAuthorized(firstSource) {
		t.Fatal("valid response was rejected after replay flood")
	}
}

func TestRelayRejectsExpiredPathChallenge(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 2, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("expired-path!!!!"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 31
	original := mustRelayUDPAddr(t, "127.0.0.1:10301")
	additional := mustRelayUDPAddr(t, "127.0.0.1:10302")
	session, err := router.registerWithPathAuth(sessionID, original, pathKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	clientNonce := [pathControlNonceSize]byte{8, 6, 7, 5}
	key, ok := newSourceAddrKey(additional)
	if !ok {
		t.Fatal("additional source address is not routable")
	}
	expiredCookie := newPathCookie(pathKey, sessionID, key, clientNonce, time.Now().Add(-pathChallengeLifetime-time.Second))
	response, err := marshalPathControl(pathControlResponse, sessionID, clientNonce, expiredCookie, pathKey)
	if err != nil {
		t.Fatal(err)
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: response, from: additional}, mustParsePathControl(t, response))
	if session.IsSourceAuthorized(additional) {
		t.Fatal("expired path challenge was accepted")
	}
}

func TestRelayDoesNotAdmitAdditionalPathWhenMigrationDisabled(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 2, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("fixed-path-only!"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 41
	original := mustRelayUDPAddr(t, "127.0.0.1:10401")
	additional := mustRelayUDPAddr(t, "127.0.0.1:10402")
	session, err := router.registerWithPathAuth(sessionID, original, pathKey, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	nonce := [pathControlNonceSize]byte{1, 2, 3, 4}
	request, err := marshalPathControl(pathControlRequest, sessionID, nonce, [pathControlNonceSize]byte{}, pathKey)
	if err != nil {
		t.Fatal(err)
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: request, from: additional}, mustParsePathControl(t, request))
	transport.assertNoWrite(t)
	if session.IsSourceAuthorized(additional) {
		t.Fatal("additional path was admitted while migration was disabled")
	}
}

func TestRelayOldPathUnseenPacketDoesNotChangeActiveReturnPath(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 4, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("stable-return-id"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 51
	original := mustRelayUDPAddr(t, "127.0.0.1:10501")
	additional := mustRelayUDPAddr(t, "127.0.0.1:10502")
	sessionTransport, err := router.registerWithPathAuth(sessionID, original, pathKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionTransport.Close()
	authenticateRelayTestPath(t, router, transport, sessionID, pathKey, additional)

	var sendKey [trafficKeySize]byte
	var recvKey [trafficKeySize]byte
	recvKey[0] = 61
	session, err := NewDatagramSession(SessionOptions{
		ID: sessionID, Transport: sessionTransport, RemoteAddr: original,
		SendKey: sendKey, RecvKey: recvKey, Pacer: NewTokenBucketPacer(100000),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	codec, err := NewCodec(recvKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("unseen old path packet")
	header, err := NewDataHeader(sessionID, 15, 101, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := codec.Seal(101, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	router.routeData(relayPacketEnvelope{packet: wire, from: original})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := session.RecvPacket(ctx, 15); err != nil || string(got) != string(payload) {
		t.Fatalf("old path payload = %q, err=%v", got, err)
	}
	if err := session.SendPacket(ctx, 15, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	write := transport.nextWrite(t)
	if !sameAddr(write.addr, additional) {
		t.Fatalf("reply path = %v, want challenge-selected %v", write.addr, additional)
	}
	if stats := session.Stats(); stats.Migrations != 0 {
		t.Fatalf("business data changed session return state: %#v", stats)
	}
}

func TestRelayInvalidFECDoesNotChangeActiveReturnPath(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 4, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("bad-fec-return!!"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 71
	original := mustRelayUDPAddr(t, "127.0.0.1:10601")
	additional := mustRelayUDPAddr(t, "127.0.0.1:10602")
	sessionTransport, err := router.registerWithPathAuth(sessionID, original, pathKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionTransport.Close()
	authenticateRelayTestPath(t, router, transport, sessionID, pathKey, additional)

	var sendKey [trafficKeySize]byte
	var recvKey [trafficKeySize]byte
	recvKey[0] = 81
	session, err := NewDatagramSession(SessionOptions{
		ID: sessionID, Transport: sessionTransport, RemoteAddr: original,
		SendKey: sendKey, RecvKey: recvKey, Pacer: NewTokenBucketPacer(100000),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	codec, err := NewCodec(recvKey)
	if err != nil {
		t.Fatal(err)
	}
	header, err := NewDataHeader(sessionID, 16, 102, 3)
	if err != nil {
		t.Fatal(err)
	}
	header.FECGroup = 1
	header.FECIndex = 0
	header.FECTotal = 2
	header.FECDataShards = 2
	wire, err := codec.Seal(102, header, []byte("bad"))
	if err != nil {
		t.Fatal(err)
	}
	router.routeData(relayPacketEnvelope{packet: wire, from: original})
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.SendPacket(ctx, 16, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	write := transport.nextWrite(t)
	if !sameAddr(write.addr, additional) {
		t.Fatalf("reply path after invalid FEC = %v, want %v", write.addr, additional)
	}
}

func TestRelayContinuousNATRebindSafelyReplacesInactivePaths(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 4, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("many-rebinds-id!"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 93
	original := mustRelayUDPAddr(t, "127.0.0.1:10801")
	session, err := router.registerWithPathAuth(sessionID, original, pathKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	var firstRebind net.Addr
	var latest net.Addr
	for index := 0; index < defaultRelayMaxPathsPerSession+12; index++ {
		source := mustRelayUDPAddr(t, fmt.Sprintf("127.0.0.1:%d", 13000+index))
		if index == 0 {
			firstRebind = source
		}
		latest = source
		authenticateRelayTestPath(t, router, transport, sessionID, pathKey, source)
		if !session.IsSourceAuthorized(source) {
			t.Fatalf("rebind %d was not authorized", index)
		}
		router.mu.Lock()
		pathCount := len(session.paths)
		active := session.activeSource
		router.mu.Unlock()
		wantActive, _ := newSourceAddrKey(source)
		if pathCount > defaultRelayMaxPathsPerSession {
			t.Fatalf("path count = %d, exceeds %d", pathCount, defaultRelayMaxPathsPerSession)
		}
		if active != wantActive {
			t.Fatalf("active source after rebind %d = %#v, want %#v", index, active, wantActive)
		}
	}
	if session.IsSourceAuthorized(firstRebind) {
		t.Fatal("oldest inactive path survived bounded replacement")
	}
	if err := session.WritePacket(context.Background(), []byte("reply"), original); err != nil {
		t.Fatal(err)
	}
	if write := transport.nextWrite(t); !sameAddr(write.addr, latest) {
		t.Fatalf("reply path = %v, want latest rebind %v", write.addr, latest)
	}
}

func TestRelayAgesOutInactivePathWithoutRemovingActivePath(t *testing.T) {
	transport := newPathControlCaptureTransport()
	router := newRelayTransportRouter(transport, 4, 1)
	var sessionID SessionID
	copy(sessionID[:], []byte("aged-path-id!!!!"))
	var pathKey [trafficKeySize]byte
	pathKey[0] = 94
	original := mustRelayUDPAddr(t, "127.0.0.1:10901")
	active := mustRelayUDPAddr(t, "127.0.0.1:10902")
	session, err := router.registerWithPathAuth(sessionID, original, pathKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	authenticateRelayTestPath(t, router, transport, sessionID, pathKey, active)
	originalKey, _ := newSourceAddrKey(original)
	router.mu.Lock()
	old := session.paths[originalKey]
	old.lastSeen = time.Now().Add(-pathAuthorizationLifetime - time.Second)
	session.paths[originalKey] = old
	router.mu.Unlock()

	if session.IsSourceAuthorized(original) {
		t.Fatal("expired inactive path remained authorized")
	}
	if !session.IsSourceAuthorized(active) {
		t.Fatal("active path was removed by path aging")
	}
	router.mu.Lock()
	_, globallyMapped := router.sources[originalKey]
	router.mu.Unlock()
	if globallyMapped {
		t.Fatal("expired path remained in relay source demux")
	}
}

func TestRelayMultipathRegistersSourcesAndDeduplicatesData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gotCh := make(chan RelayPacket, 4)
	relay, err := NewRelay(RelayOptions{
		Transport: serverTransport, PacerPPS: 100000,
		AuthKey: []byte("multipath-test-psk-0123456789"),
		Handler: RelayHandlerFunc(func(_ context.Context, packet RelayPacket) error {
			gotCh <- packet
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go func() { _ = relay.ListenAndServe(ctx) }()

	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: serverTransport.LocalAddr().String(),
		LocalAddrs: []string{"127.0.0.1:0", "127.0.0.1:0"},
		PacerPPS:   100000, HandshakeTimeout: time.Second,
		AuthKey: []byte("multipath-test-psk-0123456789"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.SendPacket(ctx, capturedPacketStreamID, mustTunnelPayload(t, "first multipath")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gotCh:
	case <-ctx.Done():
		t.Fatal("first multipath packet was not delivered")
	}

	waitForRelaySourceCount(t, relay, 2)
	if err := manager.SendPacket(ctx, capturedPacketStreamID, mustTunnelPayload(t, "deduplicated multipath")); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-gotCh:
		datagram, err := ParseTunnelDatagram(packet.Payload)
		if err != nil || string(datagram.Payload) != "deduplicated multipath" {
			t.Fatalf("unexpected multipath payload: %q err=%v", datagram.Payload, err)
		}
	case <-ctx.Done():
		t.Fatal("multipath packet was not delivered")
	}
	select {
	case duplicate := <-gotCh:
		t.Fatalf("multipath duplicate reached relay handler: %q", duplicate.Payload)
	case <-time.After(100 * time.Millisecond):
	}
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

type pathControlWrite struct {
	packet []byte
	addr   net.Addr
}

type pathControlCaptureTransport struct {
	writes chan pathControlWrite
}

func newPathControlCaptureTransport() *pathControlCaptureTransport {
	return &pathControlCaptureTransport{writes: make(chan pathControlWrite, 8192)}
}

func (t *pathControlCaptureTransport) WritePacket(ctx context.Context, packet []byte, addr net.Addr) error {
	select {
	case t.writes <- pathControlWrite{packet: append([]byte(nil), packet...), addr: addr}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *pathControlCaptureTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *pathControlCaptureTransport) LocalAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:443")
	return addr
}

func (t *pathControlCaptureTransport) Close() error { return nil }

func (t *pathControlCaptureTransport) nextWrite(testingT *testing.T) pathControlWrite {
	testingT.Helper()
	select {
	case write := <-t.writes:
		return write
	case <-time.After(time.Second):
		testingT.Fatal("timed out waiting for path control write")
		return pathControlWrite{}
	}
}

func (t *pathControlCaptureTransport) assertNoWrite(testingT *testing.T) {
	testingT.Helper()
	select {
	case write := <-t.writes:
		testingT.Fatalf("unexpected path control write to %v: %x", write.addr, write.packet)
	case <-time.After(20 * time.Millisecond):
	}
}

func mustParsePathControl(t *testing.T, wire []byte) pathControlMessage {
	t.Helper()
	msg, err := parsePathControl(wire)
	if err != nil {
		t.Fatalf("parse path control: %v", err)
	}
	return msg
}

func waitForRelaySourceCount(t *testing.T, relay *Relay, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		relay.mu.Lock()
		router := relay.router
		relay.mu.Unlock()
		if router != nil {
			router.mu.Lock()
			count := len(router.sources)
			router.mu.Unlock()
			if count == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay source count did not reach %d", want)
}

func authenticateRelayTestPath(t *testing.T, router *relayTransportRouter, transport *pathControlCaptureTransport, sessionID SessionID, pathKey [trafficKeySize]byte, source net.Addr) {
	t.Helper()
	nonce, err := newPathNonce()
	if err != nil {
		t.Fatal(err)
	}
	request, err := marshalPathControl(pathControlRequest, sessionID, nonce, [pathControlNonceSize]byte{}, pathKey)
	if err != nil {
		t.Fatal(err)
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: request, from: source}, mustParsePathControl(t, request))
	challenge := mustParsePathControl(t, transport.nextWrite(t).packet)
	response, err := marshalPathControl(pathControlResponse, sessionID, challenge.clientNonce, challenge.serverNonce, pathKey)
	if err != nil {
		t.Fatal(err)
	}
	router.handlePathControl(context.Background(), relayPacketEnvelope{packet: response, from: source}, mustParsePathControl(t, response))
}
