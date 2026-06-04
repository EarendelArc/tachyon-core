package app

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/pipeline"
	"github.com/tachyon-space/tachyon-core/internal/routing"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestPipelineTGPRelayWritesResponseToTUN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echo.Close()
	go serveOneUDPEcho(echo)

	relayTransport, err := tgp.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	relay, err := tgp.NewRelay(tgp.RelayOptions{
		Transport: relayTransport,
		PacerPPS:  100000,
		Handler: serverRelayHandler{
			forwarder: netUDPForwarder{timeout: time.Second},
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

	echoAddr := netip.MustParseAddrPort(echo.LocalAddr().String())
	localAddr := netip.MustParseAddrPort("198.18.0.2:53000")
	outbound, err := buildIPv4UDPPacket(localAddr, echoAddr, []byte("ping"))
	if err != nil {
		t.Fatalf("build outbound packet: %v", err)
	}
	device := &integrationTUNDevice{
		packet:  outbound,
		written: make(chan []byte, 1),
	}

	manager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr:       relayTransport.LocalAddr().String(),
		LocalAddr:        "127.0.0.1:0",
		PacerPPS:         100000,
		HandshakeTimeout: time.Second,
		OnDatagram: func(_ context.Context, datagram tgp.TunnelDatagram) error {
			packet, err := buildIPv4UDPPacket(datagram.RemoteAddrPort(), datagram.LocalAddrPort(), datagram.Payload)
			if err != nil {
				return err
			}
			return device.WritePacket(packet)
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer manager.Close()

	packetPipeline := pipeline.New(pipeline.Options{
		Device:  device,
		Tracker: integrationTracker{proc: pidtrack.ProcessInfo{Name: "game.exe"}},
		Router: pipeline.NewRouter(config.RoutingConfig{DefaultAction: "xray"}, routing.Engine{
			Profiles: []routing.GameProfile{
				{
					ID:          "game",
					DisplayName: "Game",
					Enabled:     true,
					Manual:      true,
					Match:       routing.MatchRule{ProcessNames: []string{"game.exe"}},
					UDPPolicy:   routing.UDPPolicyTGP,
				},
			},
		}),
		Handler: clientPacketHandler{tgp: manager},
	})
	if err := packetPipeline.Run(ctx); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	select {
	case packet := <-device.written:
		flow, payload, err := pipeline.ExtractUDPPayload(packet)
		if err != nil {
			t.Fatalf("extract writeback packet: %v", err)
		}
		if flow.LocalIP != echoAddr.Addr().String() || flow.LocalPort != echoAddr.Port() {
			t.Fatalf("unexpected response source: %#v", flow)
		}
		if flow.RemoteIP != localAddr.Addr().String() || flow.RemotePort != localAddr.Port() {
			t.Fatalf("unexpected response destination: %#v", flow)
		}
		if !bytes.Equal(payload, []byte("echo:ping")) {
			t.Fatalf("unexpected response payload: %q", payload)
		}
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-ctx.Done():
		t.Fatalf("timeout waiting for TUN writeback: %v", ctx.Err())
	}
}

func serveOneUDPEcho(conn net.PacketConn) {
	buf := make([]byte, 1500)
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(append([]byte("echo:"), buf[:n]...), from)
}

type integrationTUNDevice struct {
	packet  []byte
	read    bool
	written chan []byte
}

func (d *integrationTUNDevice) Name() string              { return "integration0" }
func (d *integrationTUNDevice) Addresses() []netip.Prefix { return nil }
func (d *integrationTUNDevice) MTU() int                  { return 1500 }
func (d *integrationTUNDevice) ReadPacket(buf []byte) (int, error) {
	if d.read {
		return 0, io.EOF
	}
	d.read = true
	return copy(buf, d.packet), nil
}
func (d *integrationTUNDevice) WritePacket(packet []byte) error {
	d.written <- append([]byte(nil), packet...)
	return nil
}
func (d *integrationTUNDevice) Close() error { return nil }

type integrationTracker struct {
	proc pidtrack.ProcessInfo
}

func (t integrationTracker) LookupFlow(context.Context, pidtrack.FlowKey) (pidtrack.ProcessInfo, error) {
	return t.proc, nil
}
