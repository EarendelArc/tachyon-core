package pipeline

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/routing"
)

type fakeDevice struct {
	packet []byte
	read   bool
}

func (d *fakeDevice) Name() string              { return "fake0" }
func (d *fakeDevice) Addresses() []netip.Prefix { return nil }
func (d *fakeDevice) MTU() int                  { return 1500 }
func (d *fakeDevice) ReadPacket(buf []byte) (int, error) {
	if d.read {
		return 0, io.EOF
	}
	d.read = true
	return copy(buf, d.packet), nil
}
func (d *fakeDevice) WritePacket([]byte) error { return nil }
func (d *fakeDevice) Close() error             { return nil }

type fakeTracker struct {
	proc pidtrack.ProcessInfo
	err  error
}

func (t fakeTracker) LookupFlow(context.Context, pidtrack.FlowKey) (pidtrack.ProcessInfo, error) {
	return t.proc, t.err
}

func TestPipelineReadsLooksUpAndDecides(t *testing.T) {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[12:16], []byte{198, 18, 0, 2})
	copy(packet[16:20], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 27015)

	var got Decision
	p := New(Options{
		Device:  &fakeDevice{packet: packet},
		Tracker: fakeTracker{proc: pidtrack.ProcessInfo{Name: "game.exe"}},
		Router: NewRouter(config.RoutingConfig{DefaultAction: "direct"}, routing.Engine{
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
		Handler: HandlerFunc(func(ctx context.Context, decision Decision, packet []byte) error {
			got = decision
			return nil
		}),
	})

	if err := p.Run(context.Background()); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}
	if got.Action != ActionTGP {
		t.Fatalf("expected tgp decision, got %#v", got)
	}
	if stats := p.Snapshot(); stats.PacketsRead != 1 || stats.DecidedTGP != 1 || stats.BytesRead != uint64(len(packet)) || stats.BytesTGP != uint64(len(packet)) {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestPipelineStopsOnFatalHandlerError(t *testing.T) {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[12:16], []byte{198, 18, 0, 2})
	copy(packet[16:20], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 27015)

	sentinel := errors.New("captured direct traffic")
	p := New(Options{
		Device:  &fakeDevice{packet: packet},
		Tracker: fakeTracker{},
		Router:  NewRouter(config.RoutingConfig{DefaultAction: "direct"}, routing.Engine{}),
		Handler: HandlerFunc(func(context.Context, Decision, []byte) error {
			return &FatalHandlerError{Err: sentinel}
		}),
	})

	err := p.Run(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("pipeline error = %v, want fatal handler error", err)
	}
	if stats := p.Snapshot(); stats.HandlerErrors != 1 || stats.DecidedDirect != 1 {
		t.Fatalf("unexpected fail-closed stats: %#v", stats)
	}
}

func TestPipelinePIDMissStillAppliesCIDRRule(t *testing.T) {
	packet := testUDPPacket()
	lookupErr := errors.New("pid table race")
	var got Decision
	p := New(Options{
		Device:  &fakeDevice{packet: packet},
		Tracker: fakeTracker{err: lookupErr},
		Router: NewRouter(config.RoutingConfig{
			DefaultAction: "direct",
			Rules: []config.RouteRule{{
				CIDR:     "203.0.113.0/24",
				Protocol: "udp",
				Action:   "tgp",
			}},
		}, routing.Engine{}),
		Handler: HandlerFunc(func(_ context.Context, decision Decision, _ []byte) error {
			got = decision
			return nil
		}),
	})

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Action != ActionTGP || got.ProcessKnown || got.Process.Name != "" {
		t.Fatalf("decision = %#v, want CIDR TGP with unknown process", got)
	}
	if stats := p.Snapshot(); stats.LookupErrors != 1 || stats.DecidedTGP != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestPipelinePIDMissDoesNotMatchProcessRuleOrSendDirectToTGP(t *testing.T) {
	packet := testUDPPacket()
	var got Decision
	p := New(Options{
		Device:  &fakeDevice{packet: packet},
		Tracker: fakeTracker{err: errors.New("process unknown")},
		Router: NewRouter(config.RoutingConfig{
			DefaultAction: "direct",
			Rules: []config.RouteRule{{
				ProcessName: "game.exe",
				Protocol:    "udp",
				Action:      "tgp",
			}},
		}, routing.Engine{}),
		Handler: HandlerFunc(func(_ context.Context, decision Decision, _ []byte) error {
			got = decision
			if decision.Action == ActionTGP {
				t.Fatal("unknown process traffic was incorrectly sent to TGP")
			}
			return nil
		}),
	})

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Action != ActionDirect || got.ProcessKnown {
		t.Fatalf("decision = %#v, want direct with unknown process", got)
	}
}

func TestPipelinePIDMissBlocksCIDRFallbackWhenProcessTGPProfileExists(t *testing.T) {
	packet := testUDPPacket()
	var got Decision
	p := New(Options{
		Device:  &fakeDevice{packet: packet},
		Tracker: fakeTracker{err: errors.New("process unknown")},
		Router: NewRouter(config.RoutingConfig{
			DefaultAction: "direct",
			Rules: []config.RouteRule{{
				Priority: 10,
				CIDR:     "203.0.113.0/24",
				Protocol: "udp",
				Action:   "tgp",
			}},
		}, routing.Engine{Profiles: []routing.GameProfile{{
			ID:        "selected-game",
			Enabled:   true,
			Manual:    true,
			Priority:  100,
			Match:     routing.MatchRule{ProcessNames: []string{"game.exe"}},
			UDPPolicy: routing.UDPPolicyTGP,
		}}}),
		Handler: HandlerFunc(func(_ context.Context, decision Decision, _ []byte) error {
			got = decision
			return nil
		}),
	})

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Action != ActionDrop || got.ProcessKnown {
		t.Fatalf("decision = %#v, want fail-safe drop", got)
	}
}

func TestPipelinePIDMissBlocksCIDRFallbackWhenProcessTGPRuleExists(t *testing.T) {
	packet := testUDPPacket()
	var got Decision
	p := New(Options{
		Device:  &fakeDevice{packet: packet},
		Tracker: fakeTracker{err: errors.New("process unknown")},
		Router: NewRouter(config.RoutingConfig{
			DefaultAction: "direct",
			Rules: []config.RouteRule{
				{Priority: 100, ProcessName: "game.exe", Protocol: "udp", Action: "tgp"},
				{Priority: 10, CIDR: "203.0.113.0/24", Protocol: "udp", Action: "tgp"},
			},
		}, routing.Engine{}),
		Handler: HandlerFunc(func(_ context.Context, decision Decision, _ []byte) error {
			got = decision
			return nil
		}),
	})

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Action != ActionDrop || got.ProcessKnown {
		t.Fatalf("decision = %#v, want fail-safe drop", got)
	}
}

func testUDPPacket() []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[12:16], []byte{198, 18, 0, 2})
	copy(packet[16:20], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 27015)
	return packet
}
