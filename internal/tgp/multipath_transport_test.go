package tgp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMultipathTransportUsesRelayClockOffsetForPathRequests(t *testing.T) {
	for _, offset := range []time.Duration{-2 * time.Second, 2 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			path := newFakeMultipathPath("127.0.0.1:10001")
			transport, err := NewMultipathTransport(path)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			remote := mustMultipathUDPAddr(t, "127.0.0.1:443")
			var sessionID SessionID
			var key [trafficKeySize]byte
			before := time.Now().Add(offset)
			if err := transport.EnablePathAuthentication(sessionID, key, remote, offset); err != nil {
				t.Fatal(err)
			}
			request := mustParsePathControl(t, path.nextWrite(t).packet)
			after := time.Now().Add(offset)
			issuedUnix := int64(binary.BigEndian.Uint64(request.clientNonce[:8]))
			if issuedUnix < before.Unix() || issuedUnix > after.Unix() {
				t.Fatalf("path request timestamp = %d, want relay-aligned range [%d,%d]", issuedUnix, before.Unix(), after.Unix())
			}
		})
	}
}

func TestMultipathTransportFansOutWrites(t *testing.T) {
	left := newFakeMultipathPath("127.0.0.1:10001")
	right := newFakeMultipathPath("127.0.0.1:10002")
	transport, err := NewMultipathTransport(left, right)
	if err != nil {
		t.Fatalf("new multipath transport: %v", err)
	}
	defer transport.Close()

	remote := mustMultipathUDPAddr(t, "127.0.0.1:443")
	payload := []byte("game packet")
	if err := transport.WritePacket(context.Background(), payload, remote); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	leftWrite := left.nextWrite(t)
	rightWrite := right.nextWrite(t)
	if string(leftWrite.packet) != string(payload) || string(rightWrite.packet) != string(payload) {
		t.Fatalf("fanout payload mismatch: %q %q", leftWrite.packet, rightWrite.packet)
	}
	if leftWrite.addr.String() != remote.String() || rightWrite.addr.String() != remote.String() {
		t.Fatalf("fanout remote mismatch: %v %v", leftWrite.addr, rightWrite.addr)
	}
}

func TestMultipathTransportSucceedsWhenOnePathWrites(t *testing.T) {
	left := newFakeMultipathPath("127.0.0.1:10001")
	right := newFakeMultipathPath("127.0.0.1:10002")
	left.writeErr = errors.New("left path down")
	transport, err := NewMultipathTransport(left, right)
	if err != nil {
		t.Fatalf("new multipath transport: %v", err)
	}
	defer transport.Close()

	if err := transport.WritePacket(context.Background(), []byte("payload"), mustMultipathUDPAddr(t, "127.0.0.1:443")); err != nil {
		t.Fatalf("partial write should succeed: %v", err)
	}
	_ = right.nextWrite(t)
}

func TestMultipathTransportFailsWhenAllPathsFail(t *testing.T) {
	left := newFakeMultipathPath("127.0.0.1:10001")
	right := newFakeMultipathPath("127.0.0.1:10002")
	leftErr := errors.New("left path down")
	rightErr := errors.New("right path down")
	left.writeErr = leftErr
	right.writeErr = rightErr
	transport, err := NewMultipathTransport(left, right)
	if err != nil {
		t.Fatalf("new multipath transport: %v", err)
	}
	defer transport.Close()

	err = transport.WritePacket(context.Background(), []byte("payload"), mustMultipathUDPAddr(t, "127.0.0.1:443"))
	if err == nil {
		t.Fatal("all path failure should fail")
	}
	if !errors.Is(err, leftErr) || !errors.Is(err, rightErr) {
		t.Fatalf("aggregate error = %v, want both path failures", err)
	}
	if got := err.Error(); !strings.Contains(got, "path 0: left path down\npath 1: right path down") {
		t.Fatalf("aggregate error order = %q, want stable path order", got)
	}
}

func TestMultipathTransportSuccessfulResultWinsConcurrentClose(t *testing.T) {
	for iteration := 0; iteration < 5000; iteration++ {
		transportCtx, transportCancel := context.WithCancel(context.Background())
		transport := &MultipathTransport{
			ctx:         transportCtx,
			cancel:      transportCancel,
			paths:       make([]Transport, 2),
			terminalErr: ErrMultipathTransportClosed,
		}
		_, writeCancel := context.WithCancel(context.Background())
		results := make(chan multipathWriteResult, 2)
		results <- multipathWriteResult{index: 0, err: errors.New("path down")}
		results <- multipathWriteResult{index: 1}

		// Both the final successful worker publication and transport close are
		// ready before aggregation starts. The result publication must win
		// deterministically rather than depending on select case selection.
		transportCancel()
		err := transport.awaitWriteResults(
			context.Background(),
			writeCancel,
			[]int{0, 1},
			results,
		)
		if err != nil {
			t.Fatalf("iteration %d: concurrent success lost to close: %v", iteration, err)
		}
	}
}

func TestMultipathTransportCallerCancelDoesNotWaitForNonCooperativeWrite(t *testing.T) {
	path := newNonCooperativeWritePath()
	transport, err := NewMultipathTransport(path)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- transport.WritePacket(ctx, []byte("blocked"), mustMultipathUDPAddrMust("127.0.0.1:443"))
	}()
	path.waitStarted(t)
	cancel()
	assertMultipathWriteReturns(t, done, context.Canceled)
	close(path.releaseWrite)
}

func TestMultipathTransportCloseDoesNotWaitForNonCooperativeWrite(t *testing.T) {
	path := newNonCooperativeWritePath()
	transport, err := NewMultipathTransport(path)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- transport.WritePacket(context.Background(), []byte("blocked"), mustMultipathUDPAddrMust("127.0.0.1:443"))
	}()
	path.waitStarted(t)
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	assertMultipathWriteReturns(t, done, ErrMultipathTransportClosed)
	close(path.releaseWrite)
}

func assertMultipathWriteReturns(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("write error = %v, want %v", err, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("write did not return within cancellation bound")
	}
}

func TestMultipathTransportMergesReads(t *testing.T) {
	left := newFakeMultipathPath("127.0.0.1:10001")
	right := newFakeMultipathPath("127.0.0.1:10002")
	transport, err := NewMultipathTransport(left, right)
	if err != nil {
		t.Fatalf("new multipath transport: %v", err)
	}
	defer transport.Close()

	from := mustMultipathUDPAddr(t, "127.0.0.1:443")
	right.reads <- fakeMultipathRead{packet: []byte("from right"), from: from}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet, gotFrom, err := transport.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if string(packet) != "from right" || gotFrom.String() != from.String() {
		t.Fatalf("unexpected merged read: %q from %v", packet, gotFrom)
	}
}

func TestMultipathTransportClosesAllPaths(t *testing.T) {
	left := newFakeMultipathPath("127.0.0.1:10001")
	right := newFakeMultipathPath("127.0.0.1:10002")
	transport, err := NewMultipathTransport(left, right)
	if err != nil {
		t.Fatalf("new multipath transport: %v", err)
	}

	if err := transport.Close(); err != nil {
		t.Fatalf("close multipath transport: %v", err)
	}
	if !left.isClosed() || !right.isClosed() {
		t.Fatalf("paths not closed: left=%v right=%v", left.isClosed(), right.isClosed())
	}
	if left.closeCount.Load() != 1 || right.closeCount.Load() != 1 {
		t.Fatalf("path close counts = %d/%d, want 1/1", left.closeCount.Load(), right.closeCount.Load())
	}
}

func TestMultipathTransportContinuesUntilLastReadPathFails(t *testing.T) {
	left := newFakeMultipathPath("127.0.0.1:10001")
	right := newFakeMultipathPath("127.0.0.1:10002")
	transport, err := NewMultipathTransport(left, right)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	left.failRead(io.EOF)
	from := mustMultipathUDPAddr(t, "127.0.0.1:443")
	right.reads <- fakeMultipathRead{packet: []byte("surviving path"), from: from}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet, _, err := transport.ReadPacket(ctx)
	if err != nil || string(packet) != "surviving path" {
		t.Fatalf("surviving read = %q, %v", packet, err)
	}

	right.failRead(errors.New("right path failed"))
	_, _, err = transport.ReadPacket(ctx)
	if err == nil || !strings.Contains(err.Error(), "all multipath read paths failed") {
		t.Fatalf("terminal read error = %v", err)
	}
	if left.closeCount.Load() != 1 || right.closeCount.Load() != 1 {
		t.Fatalf("path close counts = %d/%d, want 1/1", left.closeCount.Load(), right.closeCount.Load())
	}
}

func TestMultipathTransportCloseCancelsInflightWrite(t *testing.T) {
	path := newFakeMultipathPath("127.0.0.1:10001")
	path.blockWrites = true
	transport, err := NewMultipathTransport(path)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- transport.WritePacket(context.Background(), []byte("blocked"), mustMultipathUDPAddrMust("127.0.0.1:443"))
	}()
	select {
	case <-path.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("in-flight write succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight write did not return after close")
	}
}

func TestMultipathTransportReturnsAfterFirstSuccessfulWrite(t *testing.T) {
	slow := newFakeMultipathPath("127.0.0.1:10001")
	slow.blockWrites = true
	fast := newFakeMultipathPath("127.0.0.1:10002")
	transport, err := NewMultipathTransport(slow, fast)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	done := make(chan error, 1)
	go func() {
		done <- transport.WritePacket(context.Background(), []byte("paced"), mustMultipathUDPAddrMust("127.0.0.1:443"))
	}()
	_ = fast.nextWrite(t)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("successful path was held up by a blocked path")
	}
}

func TestMultipathTransportRejectsForwardedChallengeFromUnknownSource(t *testing.T) {
	path := newFakeMultipathPath("127.0.0.1:10001")
	transport, err := NewMultipathTransport(path)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	configured := mustMultipathUDPAddr(t, "127.0.0.1:443")
	unknown := mustMultipathUDPAddr(t, "127.0.0.2:443")
	var sessionID SessionID
	copy(sessionID[:], []byte("client-source-id"))
	var key [trafficKeySize]byte
	key[0] = 17
	if err := transport.EnablePathAuthentication(sessionID, key, configured, 0); err != nil {
		t.Fatal(err)
	}
	request := mustParsePathControl(t, path.nextWrite(t).packet)
	if !transport.IsSourceAuthorized(configured) {
		t.Fatal("configured server source was not authorized")
	}
	if transport.IsSourceAuthorized(unknown) {
		t.Fatal("unknown server source was authorized")
	}

	serverNonce := [pathControlNonceSize]byte{4, 3, 2, 1}
	challenge, err := marshalPathControl(pathControlChallenge, sessionID, request.clientNonce, serverNonce, key)
	if err != nil {
		t.Fatal(err)
	}
	path.reads <- fakeMultipathRead{packet: challenge, from: unknown}
	path.assertNoWrite(t)
	if transport.IsSourceAuthorized(unknown) {
		t.Fatal("forwarded challenge authorized an unknown server source")
	}

	path.reads <- fakeMultipathRead{packet: challenge, from: configured}
	response := path.nextWrite(t)
	if msg := mustParsePathControl(t, response.packet); msg.msgType != pathControlResponse {
		t.Fatalf("path control type = %d, want response", msg.msgType)
	}
	if response.addr.String() != configured.String() {
		t.Fatalf("response destination = %v, want configured relay %v", response.addr, configured)
	}
}

type fakeMultipathPath struct {
	local          net.Addr
	writes         chan fakeMultipathWrite
	reads          chan fakeMultipathRead
	readErrs       chan error
	writeErr       error
	blockWrites    bool
	writeStarted   chan struct{}
	writeStartOnce sync.Once
	closed         chan struct{}
	closeOnce      sync.Once
	closeCount     atomic.Int32
}

type fakeMultipathWrite struct {
	packet []byte
	addr   net.Addr
}

type fakeMultipathRead struct {
	packet []byte
	from   net.Addr
}

type nonCooperativeWritePath struct {
	started      chan struct{}
	releaseWrite chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newNonCooperativeWritePath() *nonCooperativeWritePath {
	return &nonCooperativeWritePath{
		started:      make(chan struct{}),
		releaseWrite: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (p *nonCooperativeWritePath) WritePacket(context.Context, []byte, net.Addr) error {
	p.startOnce.Do(func() { close(p.started) })
	<-p.releaseWrite
	return errors.New("released contract-violating write")
}

func (p *nonCooperativeWritePath) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-p.closed:
		return nil, nil, io.EOF
	}
}

func (p *nonCooperativeWritePath) LocalAddr() net.Addr {
	return mustMultipathUDPAddrMust("127.0.0.1:10003")
}

func (p *nonCooperativeWritePath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *nonCooperativeWritePath) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("non-cooperative write did not start")
	}
}

func newFakeMultipathPath(local string) *fakeMultipathPath {
	return &fakeMultipathPath{
		local:        mustMultipathUDPAddrMust(local),
		writes:       make(chan fakeMultipathWrite, 4),
		reads:        make(chan fakeMultipathRead, 4),
		readErrs:     make(chan error, 1),
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (p *fakeMultipathPath) WritePacket(ctx context.Context, packet []byte, addr net.Addr) error {
	if p.writeErr != nil {
		return p.writeErr
	}
	if p.blockWrites {
		p.writeStartOnce.Do(func() { close(p.writeStarted) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.closed:
			return io.EOF
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.closed:
		return io.EOF
	case p.writes <- fakeMultipathWrite{packet: append([]byte(nil), packet...), addr: addr}:
		return nil
	}
}

func (p *fakeMultipathPath) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-p.closed:
		return nil, nil, io.EOF
	case err := <-p.readErrs:
		return nil, nil, err
	case read := <-p.reads:
		return append([]byte(nil), read.packet...), read.from, nil
	}
}

func (p *fakeMultipathPath) LocalAddr() net.Addr {
	return p.local
}

func (p *fakeMultipathPath) Close() error {
	p.closeOnce.Do(func() {
		p.closeCount.Add(1)
		close(p.closed)
	})
	return nil
}

func (p *fakeMultipathPath) failRead(err error) { p.readErrs <- err }
func (p *fakeMultipathPath) isClosed() bool {
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

func (p *fakeMultipathPath) nextWrite(t *testing.T) fakeMultipathWrite {
	t.Helper()
	select {
	case write := <-p.writes:
		return write
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for multipath write")
		return fakeMultipathWrite{}
	}
}

func (p *fakeMultipathPath) assertNoWrite(t *testing.T) {
	t.Helper()
	select {
	case write := <-p.writes:
		t.Fatalf("unexpected multipath write to %v", write.addr)
	case <-time.After(30 * time.Millisecond):
	}
}

func mustMultipathUDPAddr(t *testing.T, raw string) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		t.Fatalf("resolve udp addr %q: %v", raw, err)
	}
	return addr
}

func mustMultipathUDPAddrMust(raw string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		panic(err)
	}
	return addr
}
