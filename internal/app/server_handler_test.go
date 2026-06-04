package app

import (
	"bytes"
	"context"
	"net/netip"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestServerRelayHandlerForwardsTunnelDatagram(t *testing.T) {
	forwarder := &fakeGameUDPForwarder{}
	handler := serverRelayHandler{forwarder: forwarder}
	payload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
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

type fakeGameUDPForwarder struct {
	target  netip.AddrPort
	payload []byte
}

func (f *fakeGameUDPForwarder) ForwardUDP(_ context.Context, target netip.AddrPort, payload []byte) error {
	f.target = target
	f.payload = append([]byte(nil), payload...)
	return nil
}
