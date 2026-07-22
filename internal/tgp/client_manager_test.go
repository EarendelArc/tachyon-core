package tgp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientManagerDialsOnceAndSends(t *testing.T) {
	session := &fakeSession{state: SessionEstablished}
	dials := 0
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			dials++
			return session, nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}

	ctx := context.Background()
	if err := manager.SendPacket(ctx, 1, []byte("one")); err != nil {
		t.Fatalf("send one: %v", err)
	}
	if err := manager.SendPacket(ctx, 1, []byte("two")); err != nil {
		t.Fatalf("send two: %v", err)
	}
	if dials != 1 {
		t.Fatalf("expected one dial, got %d", dials)
	}
	if len(session.sent) != 2 || !bytes.Equal(session.sent[1], []byte("two")) {
		t.Fatalf("unexpected sent payloads: %#v", session.sent)
	}
}

func TestClientManagerUsesMultipathDialWhenMultipleLocalAddrsConfigured(t *testing.T) {
	session := &fakeSession{state: SessionEstablished}
	multipathDials := 0
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		LocalAddrs: []string{
			"127.0.0.1:0",
			"127.0.0.2:0",
		},
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			t.Fatal("single-path dial should not be used")
			return nil, nil
		},
		DialMultipath: func(_ context.Context, localAddrs []string, _ net.Addr, _ float64) (Session, error) {
			multipathDials++
			if len(localAddrs) != 2 {
				t.Fatalf("local addrs = %v, want 2 entries", localAddrs)
			}
			return session, nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}

	if err := manager.SendPacket(context.Background(), 1, []byte("one")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if multipathDials != 1 {
		t.Fatalf("expected one multipath dial, got %d", multipathDials)
	}
}

func TestClientManagerUsesSingleConfiguredLocalAddr(t *testing.T) {
	session := &fakeSession{state: SessionEstablished}
	var gotLocal string
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		LocalAddr:  "0.0.0.0:0",
		LocalAddrs: []string{
			"127.0.0.1:0",
		},
		Dial: func(_ context.Context, localAddr string, _ net.Addr, _ float64) (Session, error) {
			gotLocal = localAddr
			return session, nil
		},
		DialMultipath: func(context.Context, []string, net.Addr, float64) (Session, error) {
			t.Fatal("multipath dial should not be used for a single configured address")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}

	if err := manager.SendPacket(context.Background(), 1, []byte("one")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotLocal != "127.0.0.1:0" {
		t.Fatalf("local addr = %q, want configured addr", gotLocal)
	}
}

func TestClientManagerValidatesResolvedRemoteBeforeDial(t *testing.T) {
	dialed := false
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		ValidateRemote: func(remote net.Addr) error {
			if remote.String() != "127.0.0.1:443" {
				t.Fatalf("remote = %s", remote)
			}
			return errors.New("relay would recurse into TUN")
		},
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			dialed = true
			return &fakeSession{state: SessionEstablished}, nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	err = manager.SendPacket(context.Background(), 1, []byte("blocked"))
	if err == nil || !strings.Contains(err.Error(), "relay would recurse") {
		t.Fatalf("error = %v", err)
	}
	if dialed {
		t.Fatal("dial ran after remote validation failed")
	}
}

func TestClientManagerUsesPinnedRemoteWithoutReconnectDNS(t *testing.T) {
	pinned := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 443}
	validated := 0
	dials := 0
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr:    "must-not-resolve.invalid:443",
		PinnedRemotes: []net.Addr{pinned},
		ValidateRemote: func(remote net.Addr) error {
			validated++
			if remote.String() != pinned.String() {
				t.Fatalf("validated remote = %s, want pinned %s", remote, pinned)
			}
			return nil
		},
		Dial: func(_ context.Context, _ string, _ net.Addr, _ float64) (Session, error) {
			dials++
			return &fakeSession{state: SessionEstablished}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.sessionFor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.(*fakeSession).setState(SessionClosed)
	if _, err := manager.sessionFor(context.Background()); err != nil {
		t.Fatal(err)
	}
	if dials != 2 {
		t.Fatalf("dials = %d, want reconnect dial", dials)
	}
	if validated != 3 {
		t.Fatalf("validator calls = %d, want construction plus every dial", validated)
	}
}

func TestClientManagerLoopbackHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	serverCh := make(chan *DatagramSession, 1)
	errCh := make(chan error, 1)
	go func() {
		server, err := AcceptSession(ctx, serverTransport, 100000)
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- server
	}()

	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr:       serverTransport.LocalAddr().String(),
		LocalAddr:        "127.0.0.1:0",
		PacerPPS:         100000,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer manager.Close()

	payload := []byte("raw captured ip packet")
	if err := manager.SendPacket(ctx, 0, payload); err != nil {
		t.Fatalf("manager send: %v", err)
	}

	var server *DatagramSession
	select {
	case server = <-serverCh:
	case err := <-errCh:
		t.Fatalf("server accept: %v", err)
	case <-ctx.Done():
		t.Fatalf("server accept timeout: %v", ctx.Err())
	}
	defer server.Close()

	got, err := server.RecvPacket(ctx, 0)
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestClientManagerReceivesTunnelDatagram(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, server, err := NewLoopbackSessionPair(ctx, 100000)
	if err != nil {
		t.Fatalf("session pair: %v", err)
	}
	defer server.Close()

	gotCh := make(chan TunnelDatagram, 1)
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			return client, nil
		},
		OnDatagram: func(_ context.Context, datagram TunnelDatagram) error {
			gotCh <- datagram
			return nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer manager.Close()

	if _, err := manager.sessionFor(ctx); err != nil {
		t.Fatalf("sessionFor: %v", err)
	}
	wire, err := MarshalTunnelDatagram(TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("203.0.113.7"),
		RemotePort: 27015,
		Payload:    []byte("reply"),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := server.SendPacket(ctx, capturedPacketStreamID, wire); err != nil {
		t.Fatalf("server send: %v", err)
	}

	select {
	case got := <-gotCh:
		if !bytes.Equal(got.Payload, []byte("reply")) {
			t.Fatalf("unexpected payload: %q", got.Payload)
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for datagram: %v", ctx.Err())
	}
}

func TestClientManagerRedialsAfterSessionReadEOF(t *testing.T) {
	left := newEOFTransport()
	right := newEOFTransport()
	transport, err := NewMultipathTransport(left, right)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewDatagramSession(SessionOptions{
		ID:         SessionID{1},
		Transport:  transport,
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		Pacer:      NewTokenBucketPacer(100000),
	})
	if err != nil {
		t.Fatal(err)
	}
	second := &fakeSession{state: SessionEstablished}
	dials := 0
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			dials++
			if dials == 1 {
				return first, nil
			}
			return second, nil
		},
		OnDatagram: func(context.Context, TunnelDatagram) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	if err := manager.SendPacket(context.Background(), 1, []byte("first")); err != nil {
		t.Fatal(err)
	}
	left.fail(io.EOF)
	time.Sleep(20 * time.Millisecond)
	if first.State() != SessionEstablished {
		t.Fatalf("one failed path closed multipath session: %v", first.State())
	}
	right.fail(io.EOF)
	waitForSessionState(t, first, SessionClosed)

	if err := manager.SendPacket(context.Background(), 1, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if dials != 2 {
		t.Fatalf("dials = %d, want 2", dials)
	}
	if got := second.sentPayloads(); len(got) != 1 || !bytes.Equal(got[0], []byte("second")) {
		t.Fatalf("redial payloads = %#v", got)
	}
}

func TestClientManagerCloseIsIrreversible(t *testing.T) {
	dials := 0
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			dials++
			return &fakeSession{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureSession(context.Background()); !errors.Is(err, ErrClientManagerClosed) {
		t.Fatalf("ensure after close = %v", err)
	}
	if err := manager.SendPacket(context.Background(), 1, []byte("late")); !errors.Is(err, ErrClientManagerClosed) {
		t.Fatalf("send after close = %v", err)
	}
	if dials != 0 {
		t.Fatalf("dials after close = %d, want 0", dials)
	}
}

func TestClientManagerCloseCancelsInflightDial(t *testing.T) {
	dialStarted := make(chan struct{})
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr:       "127.0.0.1:443",
		HandshakeTimeout: time.Second,
		Dial: func(ctx context.Context, _ string, _ net.Addr, _ float64) (Session, error) {
			close(dialStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- manager.SendPacket(context.Background(), 1, []byte("dial")) }()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sendDone:
		if !errors.Is(err, ErrClientManagerClosed) {
			t.Fatalf("in-flight send error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight send did not return")
	}
}

func TestClientManagerConcurrentCloseDialAndSend(t *testing.T) {
	dialStarted := make(chan struct{})
	var startOnce sync.Once
	var dials int
	var dialMu sync.Mutex
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr:       "127.0.0.1:443",
		HandshakeTimeout: time.Second,
		Dial: func(ctx context.Context, _ string, _ net.Addr, _ float64) (Session, error) {
			dialMu.Lock()
			dials++
			dialMu.Unlock()
			startOnce.Do(func() { close(dialStarted) })
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	const senders = 32
	results := make(chan error, senders)
	for i := 0; i < senders; i++ {
		go func() {
			results <- manager.SendPacket(context.Background(), 1, []byte("concurrent"))
		}()
	}
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < senders; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrClientManagerClosed) {
				t.Fatalf("send %d error = %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("send %d did not return", i)
		}
	}
	dialMu.Lock()
	defer dialMu.Unlock()
	if dials != 1 {
		t.Fatalf("dials = %d, want 1", dials)
	}
}

func TestClientManagerCloseRejectsSessionReturnedByCanceledDial(t *testing.T) {
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	returned := &fakeSession{}
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			close(dialStarted)
			<-releaseDial
			return returned, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- manager.SendPacket(context.Background(), 1, []byte("dial")) }()
	<-dialStarted
	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close() }()
	select {
	case <-manager.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("manager close did not cancel its context")
	}
	close(releaseDial)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wait for dial completion")
	}
	if returned.State() != SessionClosed {
		t.Fatal("session returned by canceled dial was not closed")
	}
	if err := <-sendDone; !errors.Is(err, ErrClientManagerClosed) {
		t.Fatalf("send error = %v", err)
	}
}

func TestClientManagerHandshakeUsesEarlierDeadline(t *testing.T) {
	tests := []struct {
		name          string
		configured    time.Duration
		callerTimeout time.Duration
		wantUpper     time.Duration
	}{
		{name: "caller earlier", configured: 300 * time.Millisecond, callerTimeout: 40 * time.Millisecond, wantUpper: 150 * time.Millisecond},
		{name: "config earlier", configured: 40 * time.Millisecond, callerTimeout: 300 * time.Millisecond, wantUpper: 150 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deadlineSeen := make(chan time.Time, 1)
			manager, err := NewClientManager(ClientManagerOptions{
				RemoteAddr:       "127.0.0.1:443",
				HandshakeTimeout: tt.configured,
				Dial: func(ctx context.Context, _ string, _ net.Addr, _ float64) (Session, error) {
					deadline, ok := ctx.Deadline()
					if !ok {
						t.Fatal("dial context has no deadline")
					}
					deadlineSeen <- deadline
					<-ctx.Done()
					return nil, ctx.Err()
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			ctx, cancel := context.WithTimeout(context.Background(), tt.callerTimeout)
			defer cancel()
			callerDeadline, _ := ctx.Deadline()
			expected := callerDeadline
			if configuredDeadline := time.Now().Add(tt.configured); configuredDeadline.Before(expected) {
				expected = configuredDeadline
			}
			started := time.Now()
			if err := manager.EnsureSession(ctx); err == nil {
				t.Fatal("dial unexpectedly succeeded")
			}
			if elapsed := time.Since(started); elapsed > tt.wantUpper {
				t.Fatalf("dial elapsed %s, want <= %s", elapsed, tt.wantUpper)
			}
			seen := <-deadlineSeen
			if delta := seen.Sub(expected); delta < -20*time.Millisecond || delta > 20*time.Millisecond {
				t.Fatalf("dial deadline differs from earlier deadline by %s", delta)
			}
		})
	}
}

func TestClientManagerRejectsExcessiveHandshakeTimeout(t *testing.T) {
	_, err := NewClientManager(ClientManagerOptions{
		RemoteAddr:       "127.0.0.1:443",
		HandshakeTimeout: MaxHandshakeTimeout + time.Millisecond,
	})
	if err == nil {
		t.Fatal("excessive handshake timeout was accepted")
	}
}

func TestClientManagerOldReadLoopCannotClearNewSession(t *testing.T) {
	first := newControlledSession()
	first.sendErr = errors.New("first path write failed")
	first.deferClose = true
	second := newControlledSession()
	dials := 0
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			dials++
			if dials == 1 {
				return first, nil
			}
			return second, nil
		},
		OnDatagram: func(context.Context, TunnelDatagram) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.SendPacket(context.Background(), 1, []byte("fail")); err == nil {
		t.Fatal("first send unexpectedly succeeded")
	}
	if err := manager.SendPacket(context.Background(), 1, []byte("new")); err != nil {
		t.Fatal(err)
	}
	first.releaseRecv(io.EOF)
	time.Sleep(20 * time.Millisecond)
	if manager.ActiveSessions() != 1 {
		t.Fatal("old read loop cleared the replacement session")
	}
	if err := manager.SendPacket(context.Background(), 1, []byte("still new")); err != nil {
		t.Fatal(err)
	}
	if dials != 2 {
		t.Fatalf("dials = %d, want 2", dials)
	}
}

func TestClientManagerCloseWaitsForReceiveLoop(t *testing.T) {
	session := newControlledSession()
	manager, err := NewClientManager(ClientManagerOptions{
		RemoteAddr: "127.0.0.1:443",
		Dial: func(context.Context, string, net.Addr, float64) (Session, error) {
			return session, nil
		},
		OnDatagram: func(context.Context, TunnelDatagram) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.recvStarted:
	case <-time.After(time.Second):
		t.Fatal("receive loop did not start")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.recvExited:
	default:
		t.Fatal("manager close returned before receive loop exited")
	}
}

func TestDatagramSessionConcurrentCloseSendAndReadError(t *testing.T) {
	transport := newEOFTransport()
	session, err := NewDatagramSession(SessionOptions{
		ID:         SessionID{2},
		Transport:  transport,
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		Pacer:      NewTokenBucketPacer(100000),
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = session.SendPacket(context.Background(), 1, []byte("payload"))
		}()
		go func() {
			defer wg.Done()
			_ = session.Close()
		}()
	}
	transport.fail(io.EOF)
	wg.Wait()
	if session.State() != SessionClosed {
		t.Fatalf("state = %v, want closed", session.State())
	}
	if err := session.SendPacket(context.Background(), 1, []byte("late")); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("late send error = %v, want %v", err, ErrSessionClosed)
	}
}

func waitForSessionState(t *testing.T, session Session, want SessionState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if session.State() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("session state = %v, want %v", session.State(), want)
}

type fakeSession struct {
	mu     sync.Mutex
	state  SessionState
	sent   [][]byte
	done   chan struct{}
	closed bool
}

func (s *fakeSession) ID() SessionID { return SessionID{} }
func (s *fakeSession) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return SessionClosed
	}
	if s.state == 0 {
		return SessionEstablished
	}
	return s.state
}
func (s *fakeSession) SendPacket(_ context.Context, _ StreamID, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	s.sent = append(s.sent, append([]byte(nil), payload...))
	return nil
}
func (s *fakeSession) RecvPacket(ctx context.Context, _ StreamID) ([]byte, error) {
	s.mu.Lock()
	if s.done == nil {
		s.done = make(chan struct{})
	}
	done := s.done
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrSessionClosed
	}
	select {
	case <-done:
		return nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *fakeSession) Migrate(context.Context, net.Addr) error { return nil }
func (s *fakeSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.done == nil {
		s.done = make(chan struct{})
	}
	s.closed = true
	s.state = SessionClosed
	close(s.done)
	return nil
}
func (s *fakeSession) Stats() SessionStats { return SessionStats{} }

func (s *fakeSession) setState(state SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	if state == SessionClosed && !s.closed {
		if s.done == nil {
			s.done = make(chan struct{})
		}
		s.closed = true
		close(s.done)
	}
}

func (s *fakeSession) sentPayloads() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([][]byte, len(s.sent))
	for i := range s.sent {
		result[i] = append([]byte(nil), s.sent[i]...)
	}
	return result
}

type eofTransport struct {
	errCh     chan error
	closed    chan struct{}
	closeOnce sync.Once
}

type controlledSession struct {
	mu          sync.Mutex
	state       SessionState
	sendErr     error
	recvErrs    chan error
	done        chan struct{}
	closed      bool
	deferClose  bool
	recvStarted chan struct{}
	recvExited  chan struct{}
	startOnce   sync.Once
	exitOnce    sync.Once
}

func newControlledSession() *controlledSession {
	return &controlledSession{
		state:       SessionEstablished,
		recvErrs:    make(chan error, 1),
		done:        make(chan struct{}),
		recvStarted: make(chan struct{}),
		recvExited:  make(chan struct{}),
	}
}

func (s *controlledSession) ID() SessionID { return SessionID{} }
func (s *controlledSession) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}
func (s *controlledSession) SendPacket(context.Context, StreamID, []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	return s.sendErr
}
func (s *controlledSession) RecvPacket(ctx context.Context, _ StreamID) ([]byte, error) {
	s.startOnce.Do(func() { close(s.recvStarted) })
	defer s.exitOnce.Do(func() { close(s.recvExited) })
	select {
	case err := <-s.recvErrs:
		return nil, err
	case <-s.done:
		return nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *controlledSession) Migrate(context.Context, net.Addr) error { return nil }
func (s *controlledSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.state = SessionClosed
		if !s.deferClose {
			close(s.done)
		}
	}
	return nil
}
func (s *controlledSession) Stats() SessionStats { return SessionStats{} }
func (s *controlledSession) releaseRecv(err error) {
	select {
	case s.recvErrs <- err:
	case <-s.done:
	}
}

func newEOFTransport() *eofTransport {
	return &eofTransport{errCh: make(chan error, 1), closed: make(chan struct{})}
}

func (t *eofTransport) WritePacket(ctx context.Context, _ []byte, _ net.Addr) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return io.EOF
	default:
		return nil
	}
}

func (t *eofTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case err := <-t.errCh:
		return nil, nil, err
	case <-t.closed:
		return nil, nil, io.EOF
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (t *eofTransport) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (t *eofTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}
func (t *eofTransport) fail(err error) {
	select {
	case t.errCh <- err:
	case <-t.closed:
	}
}
