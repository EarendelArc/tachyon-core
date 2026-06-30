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

func TestTGPRelayEndToEndUDPEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	}()

	relayTransport, err := tgp.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	udpRelay := newUDPRelayPool(nil, time.Second, time.Second)
	defer udpRelay.Close()
	relay, err := tgp.NewRelay(tgp.RelayOptions{
		Transport: relayTransport,
		PacerPPS:  100000,
		Handler: serverRelayHandler{
			relay: udpRelay,
		},
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	defer relay.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.ListenAndServe(ctx)
	}()

	gotCh := make(chan tgp.TunnelDatagram, 1)
	manager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr:       relayTransport.LocalAddr().String(),
		LocalAddr:        "127.0.0.1:0",
		PacerPPS:         100000,
		HandshakeTimeout: time.Second,
		OnDatagram: func(_ context.Context, datagram tgp.TunnelDatagram) error {
			gotCh <- datagram
			return nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer manager.Close()

	echoAddr := netip.MustParseAddrPort(echo.LocalAddr().String())
	wire, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   echoAddr.Addr(),
		RemotePort: echoAddr.Port(),
		Payload:    []byte("ping"),
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
	if err := manager.SendPacket(ctx, tgp.StreamID(0), wire); err != nil {
		t.Fatalf("manager send: %v", err)
	}

	select {
	case got := <-gotCh:
		if !bytes.Equal(got.Payload, []byte("echo:ping")) {
			t.Fatalf("unexpected response payload: %q", got.Payload)
		}
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-ctx.Done():
		t.Fatalf("timeout waiting for response: %v", ctx.Err())
	}
}
