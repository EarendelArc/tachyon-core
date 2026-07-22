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
	transport := newEOFTransport()
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
	transport.fail(io.EOF)
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
	mu    sync.Mutex
	state SessionState
	sent  [][]byte
}

func (s *fakeSession) ID() SessionID { return SessionID{} }
func (s *fakeSession) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == 0 {
		return SessionEstablished
	}
	return s.state
}
func (s *fakeSession) SendPacket(_ context.Context, _ StreamID, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, append([]byte(nil), payload...))
	return nil
}
func (s *fakeSession) RecvPacket(context.Context, StreamID) ([]byte, error) { return nil, nil }
func (s *fakeSession) Migrate(context.Context, net.Addr) error              { return nil }
func (s *fakeSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = SessionClosed
	return nil
}
func (s *fakeSession) Stats() SessionStats { return SessionStats{} }

func (s *fakeSession) setState(state SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
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
