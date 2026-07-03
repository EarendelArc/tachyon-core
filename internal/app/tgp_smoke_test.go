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

func TestTGPRelaySmokeVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	authKey := []byte("local-smoke-psk-0123456789abcdef")
	echo := listenSmokeUDPEcho(t)
	defer echo.Close()
	deniedPortTarget := listenSmokeUDPProbe(t)
	defer deniedPortTarget.Close()

	relayTransport, err := tgp.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	udpRelay := newUDPRelayPool(nil, time.Second, time.Second)
	defer udpRelay.Close()
	echoAddr := netip.MustParseAddrPort(echo.LocalAddr().String())
	relay, err := tgp.NewRelay(tgp.RelayOptions{
		Transport: relayTransport,
		PacerPPS:  100000,
		AuthKey:   authKey,
		Handler: serverRelayHandler{
			relay: udpRelay,
			acl: mustTargetACL(t, []config.RelayTargetRule{
				{CIDR: echoAddr.Addr().String() + "/32", Ports: fmt.Sprintf("%d", echoAddr.Port())},
			}),
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

	assertSmokeHandshakeRejected(t, relayTransport.LocalAddr().String(), nil)
	assertSmokeHandshakeRejected(t, relayTransport.LocalAddr().String(), []byte("wrong-local-smoke-psk"))

	gotCh := make(chan tgp.TunnelDatagram, 4)
	manager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr:       relayTransport.LocalAddr().String(),
		LocalAddr:        "127.0.0.1:0",
		PacerPPS:         100000,
		AuthKey:          authKey,
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

	sendSmokeTunnelDatagram(t, ctx, manager, echoAddr, []byte("ping"))
	assertSmokeEchoResponse(t, ctx, gotCh, []byte("echo:ping"))

	deniedPortAddr := netip.MustParseAddrPort(deniedPortTarget.LocalAddr().String())
	sendSmokeTunnelDatagram(t, ctx, manager, deniedPortAddr, []byte("blocked-port"))
	assertNoSmokeUDPPacket(t, deniedPortTarget, 150*time.Millisecond)
	assertNoSmokeTGPResponse(t, gotCh, 150*time.Millisecond)

	unknownAddr := netip.MustParseAddrPort("203.0.113.42:27015")
	sendSmokeTunnelDatagram(t, ctx, manager, unknownAddr, []byte("blocked-target"))
	assertNoSmokeTGPResponse(t, gotCh, 150*time.Millisecond)

	select {
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	default:
	}

	assertRelayDoesNotAllowOpenTargets(t)
}

func assertSmokeHandshakeRejected(t *testing.T, remote string, authKey []byte) {
	t.Helper()
	manager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr:       remote,
		LocalAddr:        "127.0.0.1:0",
		PacerPPS:         100000,
		AuthKey:          authKey,
		HandshakeTimeout: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	err = manager.SendPacket(ctx, tgp.StreamID(0), mustSmokeTunnelPayload(t, netip.MustParseAddrPort("127.0.0.1:9"), []byte("probe")))
	if !errors.Is(err, tgp.ErrHandshakeTimeout) {
		t.Fatalf("expected PSK handshake timeout, got %v", err)
	}
}

func assertRelayDoesNotAllowOpenTargets(t *testing.T) {
	t.Helper()
	denyAll := mustTargetACL(t, nil)
	if denyAll.Allows(netip.MustParseAddrPort("198.51.100.10:27015")) {
		t.Fatal("empty relay ACL must deny all targets")
	}
	if _, err := newTargetACL([]config.RelayTargetRule{{CIDR: "0.0.0.0/0", Ports: "1-65535"}}); err == nil {
		t.Fatal("relay ACL must reject IPv4 wildcard targets")
	}
	if _, err := newTargetACL([]config.RelayTargetRule{{CIDR: "::/0", Ports: "1-65535"}}); err == nil {
		t.Fatal("relay ACL must reject IPv6 wildcard targets")
	}
}

func listenSmokeUDPEcho(t *testing.T) net.PacketConn {
	t.Helper()
	conn := listenSmokeUDPProbe(t)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return conn
}

func listenSmokeUDPProbe(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP probe: %v", err)
	}
	return conn
}

func sendSmokeTunnelDatagram(t *testing.T, ctx context.Context, manager *tgp.ClientManager, target netip.AddrPort, payload []byte) {
	t.Helper()
	if err := manager.SendPacket(ctx, tgp.StreamID(0), mustSmokeTunnelPayload(t, target, payload)); err != nil {
		t.Fatalf("send TGP tunnel datagram to %s: %v", target, err)
	}
}

func mustSmokeTunnelPayload(t *testing.T, target netip.AddrPort, payload []byte) []byte {
	t.Helper()
	wire, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    netip.MustParseAddr("198.18.0.2"),
		LocalPort:  53000,
		RemoteIP:   target.Addr(),
		RemotePort: target.Port(),
		Payload:    payload,
	})
	if err != nil {
		t.Fatalf("marshal tunnel datagram: %v", err)
	}
	return wire
}

func assertSmokeEchoResponse(t *testing.T, ctx context.Context, gotCh <-chan tgp.TunnelDatagram, want []byte) {
	t.Helper()
	select {
	case got := <-gotCh:
		if !bytes.Equal(got.Payload, want) {
			t.Fatalf("unexpected smoke response payload: %q, want %q", got.Payload, want)
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for smoke response: %v", ctx.Err())
	}
}

func assertNoSmokeTGPResponse(t *testing.T, gotCh <-chan tgp.TunnelDatagram, wait time.Duration) {
	t.Helper()
	select {
	case got := <-gotCh:
		t.Fatalf("unexpected TGP response for denied target: %q from %s", got.Payload, got.RemoteAddrPort())
	case <-time.After(wait):
	}
}

func assertNoSmokeUDPPacket(t *testing.T, conn net.PacketConn, wait time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatalf("set UDP probe deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, from, err := conn.ReadFrom(buf)
	if err == nil {
		t.Fatalf("denied target received UDP packet from %s: %q", from, buf[:n])
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read denied UDP target: %v", err)
	}
}
