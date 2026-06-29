package tgp

import (
	"bytes"
	"context"
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

type migrationRead struct {
	packet []byte
	from   net.Addr
}

type migrationTestTransport struct {
	reads     chan migrationRead
	writes    chan net.Addr
	localAddr net.Addr
	closed    chan struct{}
	closeOnce sync.Once
}

func newMigrationTestTransport() *migrationTestTransport {
	return &migrationTestTransport{
		reads:     make(chan migrationRead, 4),
		writes:    make(chan net.Addr, 4),
		localAddr: mustUDPAddr(nil, "127.0.0.1:0"),
		closed:    make(chan struct{}),
	}
}

func (t *migrationTestTransport) inject(packet []byte, from net.Addr) {
	t.reads <- migrationRead{packet: append([]byte(nil), packet...), from: from}
}

func (t *migrationTestTransport) WritePacket(ctx context.Context, _ []byte, addr net.Addr) error {
	select {
	case t.writes <- addr:
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
