package tgp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
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

func TestDatagramSessionMigratesOnAuthenticatedSourceChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sessionID SessionID
	copy(sessionID[:], []byte("migration-test!!"))
	var sendKey [trafficKeySize]byte
	var recvKey [trafficKeySize]byte
	for i := range sendKey {
		sendKey[i] = byte(i + 1)
		recvKey[i] = byte(255 - i)
	}

	initialAddr := mustUDPAddr(t, "127.0.0.1:30000")
	migratedAddr := mustUDPAddr(t, "127.0.0.1:30001")
	transport := newMigrationTestTransport()
	session, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  transport,
		RemoteAddr: initialAddr,
		SendKey:    sendKey,
		RecvKey:    recvKey,
		Pacer:      NewTokenBucketPacer(100000),
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	codec, err := NewCodec(recvKey)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	payload := []byte("packet from a new path")
	header, err := NewDataHeader(sessionID, 9, 1, len(payload))
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	wire, err := codec.Seal(1, header, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	transport.inject(wire, migratedAddr)
	got, err := session.RecvPacket(ctx, 9)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if stats := session.Stats(); stats.Migrations != 1 {
		t.Fatalf("expected one migration, got %#v", stats)
	}

	if err := session.SendPacket(ctx, 9, []byte("reply on new path")); err != nil {
		t.Fatalf("send after migration: %v", err)
	}
	if gotAddr := transport.nextWriteAddr(ctx); !sameAddr(gotAddr, migratedAddr) {
		t.Fatalf("send used %v, want migrated addr %v", gotAddr, migratedAddr)
	}
}

func TestDatagramSessionRejectsSourceChangeWhenMigrationDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sessionID SessionID
	copy(sessionID[:], []byte("migration-off!!!"))
	var sendKey [trafficKeySize]byte
	var recvKey [trafficKeySize]byte
	for i := range sendKey {
		sendKey[i] = byte(i + 3)
		recvKey[i] = byte(203 - i)
	}

	initialAddr := mustUDPAddr(t, "127.0.0.1:30100")
	migratedAddr := mustUDPAddr(t, "127.0.0.1:30101")
	transport := newMigrationTestTransport()
	session, err := NewDatagramSession(SessionOptions{
		ID:               sessionID,
		Transport:        transport,
		RemoteAddr:       initialAddr,
		SendKey:          sendKey,
		RecvKey:          recvKey,
		Pacer:            NewTokenBucketPacer(100000),
		DisableMigration: true,
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	if err := session.Migrate(ctx, migratedAddr); !errors.Is(err, ErrMigrationDisabled) {
		t.Fatalf("manual migration error = %v, want %v", err, ErrMigrationDisabled)
	}

	codec, err := NewCodec(recvKey)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	payload := []byte("packet from rejected path")
	header, err := NewDataHeader(sessionID, 9, 1, len(payload))
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	wire, err := codec.Seal(1, header, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	transport.inject(wire, migratedAddr)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	if _, err := session.RecvPacket(shortCtx, 9); err == nil {
		shortCancel()
		t.Fatal("packet from migrated source was delivered while migration disabled")
	}
	shortCancel()
	if stats := session.Stats(); stats.Migrations != 0 {
		t.Fatalf("unexpected migration stats: %#v", stats)
	}

	transport.inject(wire, initialAddr)
	got, err := session.RecvPacket(ctx, 9)
	if err != nil {
		t.Fatalf("recv original source: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestDatagramSessionDropsDuplicatePacketNumbers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sessionID SessionID
	copy(sessionID[:], []byte("dedup-window-test"))
	var sendKey [trafficKeySize]byte
	var recvKey [trafficKeySize]byte
	for i := range sendKey {
		sendKey[i] = byte(32 + i)
		recvKey[i] = byte(64 + i)
	}

	remoteAddr := mustUDPAddr(t, "127.0.0.1:31000")
	transport := newMigrationTestTransport()
	session, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  transport,
		RemoteAddr: remoteAddr,
		SendKey:    sendKey,
		RecvKey:    recvKey,
		Pacer:      NewTokenBucketPacer(100000),
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	codec, err := NewCodec(recvKey)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	payload := []byte("multipath duplicate")
	header, err := NewDataHeader(sessionID, 12, 99, len(payload))
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	wire, err := codec.Seal(99, header, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	transport.inject(wire, remoteAddr)
	transport.inject(wire, remoteAddr)

	got, err := session.RecvPacket(ctx, 12)
	if err != nil {
		t.Fatalf("recv first packet: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer shortCancel()
	if _, err := session.RecvPacket(shortCtx, 12); err == nil {
		t.Fatal("duplicate packet was delivered")
	}
	if stats := session.Stats(); stats.BytesReceived != uint64(len(payload)) {
		t.Fatalf("duplicate counted as received bytes: %#v", stats)
	}
}

func TestDatagramSessionReplayFromAlternateSourceDoesNotMigrate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sessionID SessionID
	copy(sessionID[:], []byte("replay-no-migrate"))
	var sendKey [trafficKeySize]byte
	var recvKey [trafficKeySize]byte
	recvKey[0] = 77
	initialAddr := mustUDPAddr(t, "127.0.0.1:31100")
	replayAddr := mustUDPAddr(t, "127.0.0.1:31101")
	transport := newMigrationTestTransport()
	session, err := NewDatagramSession(SessionOptions{
		ID: sessionID, Transport: transport, RemoteAddr: initialAddr,
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
	payload := []byte("authenticated once")
	header, err := NewDataHeader(sessionID, 13, 7, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := codec.Seal(7, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(wire, initialAddr)
	if _, err := session.RecvPacket(ctx, 13); err != nil {
		t.Fatal(err)
	}
	transport.inject(wire, replayAddr)
	time.Sleep(20 * time.Millisecond)
	if stats := session.Stats(); stats.Migrations != 0 {
		t.Fatalf("replayed packet changed the session path: %#v", stats)
	}
	if err := session.SendPacket(ctx, 13, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	if got := transport.nextWriteAddr(ctx); !sameAddr(got, initialAddr) {
		t.Fatalf("reply path = %v, want original %v", got, initialAddr)
	}
}

func TestPacketDedupWindowRejectsReplayAfterEviction(t *testing.T) {
	window := newPacketDedupWindow(4)
	for packetNumber := uint64(10); packetNumber <= 14; packetNumber++ {
		if !window.SeenFirst(packetNumber) {
			t.Fatalf("new packet %d was rejected", packetNumber)
		}
	}
	if window.SeenFirst(10) {
		t.Fatal("packet older than the anti-replay window was accepted")
	}
	if window.SeenFirst(14) {
		t.Fatal("duplicate packet inside the anti-replay window was accepted")
	}
	if !window.SeenFirst(15) {
		t.Fatal("new packet after replay checks was rejected")
	}

	outOfOrder := newPacketDedupWindow(4)
	if !outOfOrder.SeenFirst(20) || !outOfOrder.SeenFirst(22) || !outOfOrder.SeenFirst(21) {
		t.Fatal("unseen out-of-order packet inside the anti-replay window was rejected")
	}
}

func TestDatagramSessionRecoversFECMissingShard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sessionID SessionID
	copy(sessionID[:], []byte("fec-session-test"))
	var sendKey [trafficKeySize]byte
	var recvKey [trafficKeySize]byte
	for i := range sendKey {
		sendKey[i] = byte(91 + i)
		recvKey[i] = byte(123 + i)
	}

	remoteAddr := mustUDPAddr(t, "127.0.0.1:32000")
	transport := newMigrationTestTransport()
	session, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  transport,
		RemoteAddr: remoteAddr,
		SendKey:    sendKey,
		RecvKey:    recvKey,
		Pacer:      NewTokenBucketPacer(100000),
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	fecCodec := NewReedSolomonCodec()
	data := [][]byte{[]byte("alpha"), []byte("bravo")}
	shards, err := fecCodec.Encode(data, 2, 1)
	if err != nil {
		t.Fatalf("encode fec: %v", err)
	}
	wireCodec, err := NewCodec(recvKey)
	if err != nil {
		t.Fatalf("wire codec: %v", err)
	}

	dataHeader, err := NewDataHeader(sessionID, 21, 1, len(shards[0]))
	if err != nil {
		t.Fatalf("data header: %v", err)
	}
	dataHeader.FECGroup = 77
	dataHeader.FECIndex = 0
	dataHeader.FECTotal = 3
	dataHeader.FECDataShards = 2
	dataWire, err := wireCodec.Seal(1, dataHeader, shards[0])
	if err != nil {
		t.Fatalf("seal data: %v", err)
	}

	parityHeader, err := NewDataHeader(sessionID, 21, 3, len(shards[2]))
	if err != nil {
		t.Fatalf("parity header: %v", err)
	}
	parityHeader.Flags |= FlagFEC
	parityHeader.FECGroup = 77
	parityHeader.FECIndex = 2
	parityHeader.FECTotal = 3
	parityHeader.FECDataShards = 2
	parityWire, err := wireCodec.Seal(3, parityHeader, shards[2])
	if err != nil {
		t.Fatalf("seal parity: %v", err)
	}

	transport.inject(dataWire, remoteAddr)
	got, err := session.RecvPacket(ctx, 21)
	if err != nil {
		t.Fatalf("recv data shard: %v", err)
	}
	if !bytes.Equal(got, data[0]) {
		t.Fatalf("first payload mismatch: %q != %q", got, data[0])
	}

	transport.inject(parityWire, remoteAddr)
	got, err = session.RecvPacket(ctx, 21)
	if err != nil {
		t.Fatalf("recv recovered shard: %v", err)
	}
	if !bytes.Equal(got, data[1]) {
		t.Fatalf("recovered payload mismatch: %q != %q", got, data[1])
	}
	stats := session.Stats()
	if stats.FECRecovered != 1 {
		t.Fatalf("expected one recovered shard, got %#v", stats)
	}
	if stats.BytesReceived != uint64(len(data[0])+len(data[1])) {
		t.Fatalf("unexpected received bytes after FEC recovery: %#v", stats)
	}
}

func TestDatagramSessionSendSideFECParityRecoversDroppedDataShard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sessionID SessionID
	copy(sessionID[:], []byte("fec-send-test!!!"))
	var clientToServerKey [trafficKeySize]byte
	var serverToClientKey [trafficKeySize]byte
	for i := range clientToServerKey {
		clientToServerKey[i] = byte(11 + i)
		serverToClientKey[i] = byte(211 - i)
	}

	clientTransport := newMigrationTestTransport()
	serverTransport := newMigrationTestTransport()
	serverAddr := mustUDPAddr(t, "127.0.0.1:33000")
	clientAddr := mustUDPAddr(t, "127.0.0.1:33001")

	client, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  clientTransport,
		RemoteAddr: serverAddr,
		SendKey:    clientToServerKey,
		RecvKey:    serverToClientKey,
		Pacer:      NewTokenBucketPacer(100000),
		FEC:        FECOptions{DataShards: 2, ParityShards: 1},
	})
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	defer client.Close()
	server, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  serverTransport,
		RemoteAddr: clientAddr,
		SendKey:    serverToClientKey,
		RecvKey:    clientToServerKey,
		Pacer:      NewTokenBucketPacer(100000),
		FEC:        FECOptions{DataShards: 2, ParityShards: 1},
	})
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	defer server.Close()

	if err := client.SendPacket(ctx, 23, []byte("alpha")); err != nil {
		t.Fatalf("send alpha: %v", err)
	}
	data0 := clientTransport.nextWritePacket(ctx)
	if err := client.SendPacket(ctx, 23, []byte("bravo is longer")); err != nil {
		t.Fatalf("send bravo: %v", err)
	}
	_ = clientTransport.nextWritePacket(ctx) // Drop data1 to force FEC recovery.
	parity := clientTransport.nextWritePacket(ctx)

	serverTransport.inject(data0, clientAddr)
	got, err := server.RecvPacket(ctx, 23)
	if err != nil {
		t.Fatalf("recv first data: %v", err)
	}
	if !bytes.Equal(got, []byte("alpha")) {
		t.Fatalf("first payload mismatch: %q", got)
	}

	serverTransport.inject(parity, clientAddr)
	got, err = server.RecvPacket(ctx, 23)
	if err != nil {
		t.Fatalf("recv recovered data: %v", err)
	}
	if !bytes.Equal(got, []byte("bravo is longer")) {
		t.Fatalf("recovered payload mismatch: %q", got)
	}
	if stats := server.Stats(); stats.FECRecovered != 1 {
		t.Fatalf("expected one recovered shard, got %#v", stats)
	}
	if stats := client.Stats(); stats.BytesSent != uint64(len("alpha")+len("bravo is longer")) {
		t.Fatalf("parity should not inflate application bytes sent: %#v", stats)
	}
}

func TestDatagramSessionFlushesPartialFECGroupOnTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sessionID SessionID
	copy(sessionID[:], []byte("fec-timeout-test"))
	var clientToServerKey [trafficKeySize]byte
	var serverToClientKey [trafficKeySize]byte
	for i := range clientToServerKey {
		clientToServerKey[i] = byte(71 + i)
		serverToClientKey[i] = byte(171 - i)
	}

	clientTransport := newMigrationTestTransport()
	serverTransport := newMigrationTestTransport()
	serverAddr := mustUDPAddr(t, "127.0.0.1:34000")
	clientAddr := mustUDPAddr(t, "127.0.0.1:34001")

	client, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  clientTransport,
		RemoteAddr: serverAddr,
		SendKey:    clientToServerKey,
		RecvKey:    serverToClientKey,
		Pacer:      NewTokenBucketPacer(100000),
		FEC:        FECOptions{DataShards: 2, ParityShards: 1, GroupTimeout: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	defer client.Close()
	server, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  serverTransport,
		RemoteAddr: clientAddr,
		SendKey:    serverToClientKey,
		RecvKey:    clientToServerKey,
		Pacer:      NewTokenBucketPacer(100000),
		FEC:        FECOptions{DataShards: 2, ParityShards: 1, GroupTimeout: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	defer server.Close()

	if err := client.SendPacket(ctx, 24, []byte("lonely tick")); err != nil {
		t.Fatalf("send lonely tick: %v", err)
	}
	_ = clientTransport.nextWritePacket(ctx) // Drop the real data shard.
	repairData := clientTransport.nextWritePacket(ctx)
	parity := clientTransport.nextWritePacket(ctx)

	serverTransport.inject(repairData, clientAddr)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := server.RecvPacket(shortCtx, 24); err == nil {
		shortCancel()
		t.Fatal("fec-only repair shard was delivered")
	}
	shortCancel()

	serverTransport.inject(parity, clientAddr)
	got, err := server.RecvPacket(ctx, 24)
	if err != nil {
		t.Fatalf("recv recovered timeout payload: %v", err)
	}
	if !bytes.Equal(got, []byte("lonely tick")) {
		t.Fatalf("recovered timeout payload mismatch: %q", got)
	}
	if stats := server.Stats(); stats.FECRecovered != 1 {
		t.Fatalf("expected one timeout FEC recovery, got %#v", stats)
	}
}

type migrationRead struct {
	packet []byte
	from   net.Addr
}

type migrationTestTransport struct {
	reads       chan migrationRead
	writes      chan net.Addr
	writePacket chan []byte
	localAddr   net.Addr
	closed      chan struct{}
	closeOnce   sync.Once
}

func newMigrationTestTransport() *migrationTestTransport {
	return &migrationTestTransport{
		reads:       make(chan migrationRead, 8),
		writes:      make(chan net.Addr, 8),
		writePacket: make(chan []byte, 8),
		localAddr:   mustUDPAddr(nil, "127.0.0.1:0"),
		closed:      make(chan struct{}),
	}
}

func (t *migrationTestTransport) inject(packet []byte, from net.Addr) {
	t.reads <- migrationRead{packet: append([]byte(nil), packet...), from: from}
}

func (t *migrationTestTransport) WritePacket(ctx context.Context, packet []byte, addr net.Addr) error {
	select {
	case t.writes <- addr:
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return ErrSessionClosed
	}
	select {
	case t.writePacket <- append([]byte(nil), packet...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return ErrSessionClosed
	}
}

func (t *migrationTestTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case read := <-t.reads:
		return append([]byte(nil), read.packet...), read.from, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.closed:
		return nil, nil, ErrSessionClosed
	}
}

func (t *migrationTestTransport) LocalAddr() net.Addr {
	return t.localAddr
}

func (t *migrationTestTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
	})
	return nil
}

func (t *migrationTestTransport) nextWriteAddr(ctx context.Context) net.Addr {
	select {
	case addr := <-t.writes:
		return addr
	case <-ctx.Done():
		return nil
	}
}

func (t *migrationTestTransport) nextWritePacket(ctx context.Context) []byte {
	select {
	case packet := <-t.writePacket:
		return packet
	case <-ctx.Done():
		return nil
	}
}

func mustUDPAddr(t *testing.T, raw string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		if t != nil {
			t.Fatalf("resolve udp addr %q: %v", raw, err)
		}
		panic(err)
	}
	return addr
}
