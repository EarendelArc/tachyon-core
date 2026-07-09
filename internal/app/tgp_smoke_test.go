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
	relayACL := mustTargetACL(t, []config.RelayTargetRule{
		{CIDR: echoAddr.Addr().String() + "/32", Ports: fmt.Sprintf("%d", echoAddr.Port())},
	})
	relay, err := tgp.NewRelay(tgp.RelayOptions{
		Transport: relayTransport,
		PacerPPS:  100000,
		AuthKey:   authKey,
		Handler: serverRelayHandler{
			relay: udpRelay,
			acl:   relayACL,
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
	assertSmokeTargetDenied(t, relayACL, unknownAddr)
	sendSmokeTunnelDatagram(t, ctx, manager, unknownAddr, []byte("blocked-target"))
	assertNoSmokeTGPResponse(t, gotCh, 150*time.Millisecond)

	select {
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	default:
	}

	assertRelayDoesNotAllowOpenTargets(t)
}

func TestTGPRelayConfigDrivenSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	psk := "config-smoke-psk-0123456789abcdef"
	echo := listenSmokeUDPEcho(t)
	defer echo.Close()
	deniedPortTarget := listenSmokeUDPProbe(t)
	defer deniedPortTarget.Close()

	echoAddr := netip.MustParseAddrPort(echo.LocalAddr().String())
	serverCfg := smokeServerConfig(psk, []config.RelayTargetRule{
		{CIDR: echoAddr.Addr().String() + "/32", Ports: fmt.Sprintf("%d", echoAddr.Port())},
	})
	if err := serverCfg.Validate(); err != nil {
		t.Fatalf("server config should validate: %v", err)
	}

	relayTransport, err := tgp.ListenUDP(serverCfg.Server.Listen)
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	udpRelay := newUDPRelayPoolWithOptions(nil, udpRelayPoolOptions{
		DialTimeout:        serverCfg.Server.Relay.DialTimeout,
		IdleTimeout:        serverCfg.Server.Relay.IdleTimeout,
		MaxFlows:           serverCfg.Server.Relay.MaxFlows,
		MaxFlowsPerSession: serverCfg.Server.Relay.MaxFlowsPerSession,
	})
	defer udpRelay.Close()
	relayACL, err := newTargetACL(serverCfg.Server.Relay.AllowedTargets)
	if err != nil {
		t.Fatalf("relay ACL from config: %v", err)
	}
	relay, err := tgp.NewRelay(tgp.RelayOptions{
		Transport:          relayTransport,
		PacerPPS:           tgpPacerPPS(serverCfg.TGP.Pacing),
		FEC:                tgpFECOptions(serverCfg.TGP.FEC),
		DisableMigration:   !serverCfg.TGP.ConnectionMigration,
		AuthKey:            tgpAuthKey(serverCfg.TGP.Auth),
		SessionIdleTimeout: serverCfg.TGP.SessionIdleTimeout,
		MaxSessions:        serverCfg.Server.Relay.MaxSessions,
		SessionQueueSize:   serverCfg.Server.Relay.SessionQueueSize,
		HandlerConcurrency: serverCfg.Server.Relay.HandlerConcurrency,
		Handler: serverRelayHandler{
			relay: udpRelay,
			acl:   relayACL,
		},
	})
	if err != nil {
		t.Fatalf("relay from config: %v", err)
	}
	defer relay.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.ListenAndServe(ctx)
	}()

	relayAddr := relayTransport.LocalAddr().String()
	assertSmokeHandshakeRejected(t, relayAddr, nil)
	assertSmokeHandshakeRejected(t, relayAddr, []byte("wrong-config-smoke-psk"))

	gotCh := make(chan tgp.TunnelDatagram, 4)
	clientCfg := smokeClientConfig(psk, relayAddr)
	if err := clientCfg.Validate(); err != nil {
		t.Fatalf("client config should validate: %v", err)
	}
	manager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr:       clientTGPRemoteAddr(clientCfg.Client.Proxy),
		LocalAddrs:       clientTGPLocalAddrs(clientCfg.Client.Proxy, clientCfg.TGP.Multipath),
		PacerPPS:         tgpPacerPPS(clientCfg.TGP.Pacing),
		FEC:              tgpFECOptions(clientCfg.TGP.FEC),
		DisableMigration: !clientCfg.TGP.ConnectionMigration,
		AuthKey:          tgpAuthKey(clientCfg.TGP.Auth),
		HandshakeTimeout: clientCfg.TGP.HandshakeTimeout,
		OnDatagram: func(_ context.Context, datagram tgp.TunnelDatagram) error {
			gotCh <- datagram
			return nil
		},
	})
	if err != nil {
		t.Fatalf("manager from config: %v", err)
	}
	defer manager.Close()

	sendSmokeTunnelDatagram(t, ctx, manager, echoAddr, []byte("config-ping"))
	assertSmokeEchoResponse(t, ctx, gotCh, []byte("echo:config-ping"))

	deniedPortAddr := netip.MustParseAddrPort(deniedPortTarget.LocalAddr().String())
	sendSmokeTunnelDatagram(t, ctx, manager, deniedPortAddr, []byte("blocked-config-port"))
	assertNoSmokeUDPPacket(t, deniedPortTarget, 150*time.Millisecond)
	assertNoSmokeTGPResponse(t, gotCh, 150*time.Millisecond)

	unknownAddr := netip.MustParseAddrPort("203.0.113.43:27015")
	assertSmokeTargetDenied(t, relayACL, unknownAddr)
	sendSmokeTunnelDatagram(t, ctx, manager, unknownAddr, []byte("blocked-config-target"))
	assertNoSmokeTGPResponse(t, gotCh, 150*time.Millisecond)

	select {
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	default:
	}
}

func smokeServerConfig(psk string, allowedTargets []config.RelayTargetRule) *config.Config {
	return &config.Config{
		Mode: config.ModeServer,
		Server: config.ServerConfig{
			Listen: "127.0.0.1:0",
			Relay: config.RelayConfig{
				DialTimeout:        time.Second,
				IdleTimeout:        time.Second,
				MaxSessions:        4,
				SessionQueueSize:   16,
				HandlerConcurrency: 4,
				MaxFlows:           8,
				MaxFlowsPerSession: 4,
				AllowedTargets:     allowedTargets,
			},
		},
		TGP: smokeTGPConfig(psk),
	}
}

func smokeClientConfig(psk string, remoteAddr string) *config.Config {
	return &config.Config{
		Mode: config.ModeClient,
		Client: config.ClientConfig{
			Proxy: config.ProxyConfig{
				ServerAddr: remoteAddr,
				LocalAddrs: []string{
					"127.0.0.1:0",
				},
			},
		},
		TGP: smokeTGPConfig(psk),
	}
}

func smokeTGPConfig(psk string) config.TGPConfig {
	return config.TGPConfig{
		FEC: config.FECConfig{
			DataShards:   2,
			ParityShards: 1,
			GroupTimeout: 20 * time.Millisecond,
			Dynamic:      true,
			AdaptWindow:  8,
		},
		Pacing: config.PacingConfig{
			InitialRatePPS: 100000,
			MaxRatePPS:     100000,
		},
		Auth: config.TGPAuthConfig{
			PSK: psk,
		},
		ConnectionMigration: true,
		HandshakeTimeout:    time.Second,
		SessionIdleTimeout:  time.Second,
	}
}

func assertSmokeTargetDenied(t *testing.T, acl *targetACL, target netip.AddrPort) {
	t.Helper()
	if acl.Allows(target) {
		t.Fatalf("relay ACL unexpectedly allows unknown target %s", target)
	}
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
