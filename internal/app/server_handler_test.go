package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestServerRelayHandlerForwardsTunnelDatagram(t *testing.T) {
	relay := &fakeGameUDPRelay{}
	handler := serverRelayHandler{
		relay: relay,
		acl: mustTargetACL(t, []config.RelayTargetRule{
			{CIDR: "203.0.113.42/32", Ports: "27015"},
		}),
	}
	payload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("203.0.113.42"),
		RemotePort: 27015,
		Payload:    []byte("game"),
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
	err = handler.HandleRelayPacket(context.Background(), tgp.RelayPacket{
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("handle relay packet: %v", err)
	}
	if relay.target != netip.MustParseAddrPort("203.0.113.42:27015") {
		t.Fatalf("unexpected target: %s", relay.target)
	}
	if !bytes.Equal(relay.payload, []byte("game")) {
		t.Fatalf("unexpected payload: %q", relay.payload)
	}
}

func TestUDPRelayPoolSendsAsyncResponsesToSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		n, from, err := echo.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = echo.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		_, _ = echo.WriteTo(append([]byte("late:"), buf[:n]...), from)
	}()

	pool := newUDPRelayPool(nil, time.Second, time.Second)
	defer pool.Close()
	session := newFakeRelaySession()
	target := netip.MustParseAddrPort(echo.LocalAddr().String())
	handler := serverRelayHandler{
		relay: pool,
		acl: mustTargetACL(t, []config.RelayTargetRule{
			{CIDR: target.Addr().String() + "/32", Ports: fmt.Sprintf("%d", target.Port())},
		}),
	}
	payload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   target.Addr(),
		RemotePort: target.Port(),
		Payload:    []byte("game"),
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
	err = handler.HandleRelayPacket(ctx, tgp.RelayPacket{
		Session:   session,
		SessionID: session.ID(),
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("handle relay packet: %v", err)
	}

	for _, want := range [][]byte{[]byte("echo:game"), []byte("late:game")} {
		select {
		case wire := <-session.sent:
			response, err := tgp.ParseTunnelDatagram(wire)
			if err != nil {
				t.Fatalf("parse response tunnel datagram: %v", err)
			}
			if !bytes.Equal(response.Payload, want) {
				t.Fatalf("unexpected response payload: %q, want %q", response.Payload, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout waiting for response %q: %v", want, ctx.Err())
		}
	}
}

func TestUDPRelayPoolRejectsTotalFlowLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	targets := listenUDPTargets(t, 2)
	for _, target := range targets {
		defer target.Close()
	}
	pool := newUDPRelayPoolWithOptions(nil, udpRelayPoolOptions{
		DialTimeout:        time.Second,
		IdleTimeout:        time.Second,
		MaxFlows:           1,
		MaxFlowsPerSession: 10,
	})
	defer pool.Close()
	session := newFakeRelaySession()

	first := tunnelPayloadForTarget(t, netip.MustParseAddrPort(targets[0].LocalAddr().String()))
	if err := pool.ForwardUDP(ctx, tgp.RelayPacket{Session: session, SessionID: session.ID()}, first); err != nil {
		t.Fatalf("first forward: %v", err)
	}

	second := tunnelPayloadForTarget(t, netip.MustParseAddrPort(targets[1].LocalAddr().String()))
	if err := pool.ForwardUDP(ctx, tgp.RelayPacket{Session: session, SessionID: session.ID()}, second); !errors.Is(err, ErrUDPRelayFlowLimit) {
		t.Fatalf("expected total flow limit error, got %v", err)
	}
}

func TestUDPRelayPoolRejectsPerSessionFlowLimitWithoutBlockingOtherSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	targets := listenUDPTargets(t, 3)
	for _, target := range targets {
		defer target.Close()
	}
	pool := newUDPRelayPoolWithOptions(nil, udpRelayPoolOptions{
		DialTimeout:        time.Second,
		IdleTimeout:        time.Second,
		MaxFlows:           3,
		MaxFlowsPerSession: 1,
	})
	defer pool.Close()
	firstSession := newFakeRelaySession()
	secondSession := newFakeRelaySessionWithID("other-relay-sess")

	first := tunnelPayloadForTarget(t, netip.MustParseAddrPort(targets[0].LocalAddr().String()))
	if err := pool.ForwardUDP(ctx, tgp.RelayPacket{Session: firstSession, SessionID: firstSession.ID()}, first); err != nil {
		t.Fatalf("first forward: %v", err)
	}

	sameSessionSecond := tunnelPayloadForTarget(t, netip.MustParseAddrPort(targets[1].LocalAddr().String()))
	if err := pool.ForwardUDP(ctx, tgp.RelayPacket{Session: firstSession, SessionID: firstSession.ID()}, sameSessionSecond); !errors.Is(err, ErrUDPRelayFlowLimit) {
		t.Fatalf("expected per-session flow limit error, got %v", err)
	}

	otherSessionFlow := tunnelPayloadForTarget(t, netip.MustParseAddrPort(targets[2].LocalAddr().String()))
	if err := pool.ForwardUDP(ctx, tgp.RelayPacket{Session: secondSession, SessionID: secondSession.ID()}, otherSessionFlow); err != nil {
		t.Fatalf("other session should not be blocked by first session limit: %v", err)
	}
}

func TestServerRelayHandlerRejectsTargetsWithoutExplicitACL(t *testing.T) {
	relay := &fakeGameUDPRelay{}
	handler := serverRelayHandler{
		relay: relay,
		acl:   mustTargetACL(t, nil),
	}
	payload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("10.0.0.10"),
		RemotePort: 27015,
		Payload:    []byte("game"),
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
	if err := handler.HandleRelayPacket(context.Background(), tgp.RelayPacket{Payload: payload}); !errors.Is(err, ErrRelayTargetDenied) {
		t.Fatalf("expected ACL denial, got %v", err)
	}
	if relay.payload != nil {
		t.Fatalf("relay should not receive denied payload: %q", relay.payload)
	}
}

func TestServerRelayHandlerRejectsUnauthorizedPort(t *testing.T) {
	relay := &fakeGameUDPRelay{}
	handler := serverRelayHandler{
		relay: relay,
		acl: mustTargetACL(t, []config.RelayTargetRule{
			{CIDR: "203.0.113.0/24", Ports: "27015-27016"},
		}),
	}
	payload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   netip.MustParseAddr("203.0.113.42"),
		RemotePort: 9999,
		Payload:    []byte("game"),
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
	if err := handler.HandleRelayPacket(context.Background(), tgp.RelayPacket{Payload: payload}); !errors.Is(err, ErrRelayTargetDenied) {
		t.Fatalf("expected ACL denial, got %v", err)
	}
}

func mustTargetACL(t *testing.T, rules []config.RelayTargetRule) *targetACL {
	t.Helper()
	acl, err := newTargetACL(rules)
	if err != nil {
		t.Fatalf("target ACL: %v", err)
	}
	return acl
}

type fakeGameUDPRelay struct {
	target  netip.AddrPort
	payload []byte
}

func (f *fakeGameUDPRelay) ForwardUDP(_ context.Context, _ tgp.RelayPacket, datagram tgp.TunnelDatagram) error {
	f.target = datagram.RemoteAddrPort()
	f.payload = append([]byte(nil), datagram.Payload...)
	return nil
}

type fakeRelaySession struct {
	id   tgp.SessionID
	sent chan []byte
}

func newFakeRelaySession() *fakeRelaySession {
	return newFakeRelaySessionWithID("fake-relay-sess!")
}

func newFakeRelaySessionWithID(raw string) *fakeRelaySession {
	var id tgp.SessionID
	copy(id[:], []byte(raw))
	return &fakeRelaySession{
		id:   id,
		sent: make(chan []byte, 8),
	}
}

func listenUDPTargets(t *testing.T, count int) []net.PacketConn {
	t.Helper()
	targets := make([]net.PacketConn, 0, count)
	for i := 0; i < count; i++ {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			for _, target := range targets {
				_ = target.Close()
			}
			t.Fatalf("listen target: %v", err)
		}
		targets = append(targets, conn)
	}
	return targets
}

func tunnelPayloadForTarget(t *testing.T, target netip.AddrPort) tgp.TunnelDatagram {
	t.Helper()
	return tgp.TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   target.Addr(),
		RemotePort: target.Port(),
		Payload:    []byte("game"),
	}
}

func (s *fakeRelaySession) ID() tgp.SessionID       { return s.id }
func (s *fakeRelaySession) State() tgp.SessionState { return tgp.SessionEstablished }
func (s *fakeRelaySession) SendPacket(_ context.Context, _ tgp.StreamID, payload []byte) error {
	s.sent <- append([]byte(nil), payload...)
	return nil
}
func (s *fakeRelaySession) RecvPacket(context.Context, tgp.StreamID) ([]byte, error) {
	return nil, nil
}
func (s *fakeRelaySession) Migrate(context.Context, net.Addr) error { return nil }
func (s *fakeRelaySession) Close() error                            { return nil }
func (s *fakeRelaySession) Stats() tgp.SessionStats                 { return tgp.SessionStats{} }
