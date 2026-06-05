package pipeline

import (
	"context"
	"encoding/binary"
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
}

func (t fakeTracker) LookupFlow(context.Context, pidtrack.FlowKey) (pidtrack.ProcessInfo, error) {
	return t.proc, nil
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
	if stats := p.Snapshot(); stats.PacketsRead != 1 || stats.DecidedTGP != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}
