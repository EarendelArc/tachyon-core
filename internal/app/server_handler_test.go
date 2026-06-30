package app

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestServerRelayHandlerForwardsTunnelDatagram(t *testing.T) {
	relay := &fakeGameUDPRelay{}
	handler := serverRelayHandler{relay: relay}
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
	handler := serverRelayHandler{relay: pool}
	target := netip.MustParseAddrPort(echo.LocalAddr().String())
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
	var id tgp.SessionID
	copy(id[:], []byte("fake-relay-sess!"))
	return &fakeRelaySession{
		id:   id,
		sent: make(chan []byte, 8),
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
