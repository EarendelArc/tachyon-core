package app

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestServerRelayHandlerForwardsTunnelDatagram(t *testing.T) {
	forwarder := &fakeGameUDPForwarder{}
	handler := serverRelayHandler{forwarder: forwarder}
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
	if forwarder.target != netip.MustParseAddrPort("203.0.113.42:27015") {
		t.Fatalf("unexpected target: %s", forwarder.target)
	}
	if !bytes.Equal(forwarder.payload, []byte("game")) {
		t.Fatalf("unexpected payload: %q", forwarder.payload)
	}
}

func TestServerRelayHandlerSendsResponseToSession(t *testing.T) {
	forwarder := &fakeGameUDPForwarder{response: []byte("reply")}
	session := &fakeRelaySession{}
	handler := serverRelayHandler{forwarder: forwarder}
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
		Session: session,
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("handle relay packet: %v", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("expected one response packet, got %d", len(session.sent))
	}
	response, err := tgp.ParseTunnelDatagram(session.sent[0])
	if err != nil {
		t.Fatalf("parse response tunnel datagram: %v", err)
	}
	if !bytes.Equal(response.Payload, []byte("reply")) {
		t.Fatalf("unexpected response payload: %q", response.Payload)
	}
}

type fakeGameUDPForwarder struct {
	target   netip.AddrPort
	payload  []byte
	response []byte
}

func (f *fakeGameUDPForwarder) ForwardUDP(_ context.Context, target netip.AddrPort, payload []byte) ([]byte, error) {
	f.target = target
	f.payload = append([]byte(nil), payload...)
	return append([]byte(nil), f.response...), nil
}

type fakeRelaySession struct {
	sent [][]byte
}

func (s *fakeRelaySession) ID() tgp.SessionID       { return tgp.SessionID{} }
func (s *fakeRelaySession) State() tgp.SessionState { return tgp.SessionEstablished }
func (s *fakeRelaySession) SendPacket(_ context.Context, _ tgp.StreamID, payload []byte) error {
	s.sent = append(s.sent, append([]byte(nil), payload...))
	return nil
}
func (s *fakeRelaySession) RecvPacket(context.Context, tgp.StreamID) ([]byte, error) {
	return nil, nil
}
func (s *fakeRelaySession) Migrate(context.Context, net.Addr) error { return nil }
func (s *fakeRelaySession) Close() error                            { return nil }
func (s *fakeRelaySession) Stats() tgp.SessionStats                 { return tgp.SessionStats{} }
