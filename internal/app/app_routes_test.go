package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
	"github.com/tachyon-space/tachyon-core/internal/tun"
)

func TestRunClientEmptyGameRoutesReachesInstallerWithoutPlatformSupport(t *testing.T) {
	app := newRouteTestApp(t, nil)
	app.client.selectiveRoutesSupported = func() bool { return false }

	device := &routeTestDevice{name: "Tachyon"}
	app.client.newTUN = func(tun.Options) (tun.Device, error) { return device, nil }
	app.client.stableInterfaceLUID = func(tun.Device) uint64 { return 41 }

	var installed *tun.SelectiveRouteOptions
	app.client.installSelectiveRoutes = func(_ context.Context, opts tun.SelectiveRouteOptions) (tun.RouteTransaction, error) {
		installed = cloneSelectiveRouteOptions(opts)
		return &routeTestTransaction{}, nil
	}
	stopErr := errors.New("stop after route orchestration")
	app.client.newPIDTracker = func() (*pidtrack.Tracker, error) { return nil, stopErr }

	err := app.Run(context.Background())
	if !errors.Is(err, stopErr) {
		t.Fatalf("Run() error = %v, want %v", err, stopErr)
	}
	if installed == nil {
		t.Fatal("route installer was not called")
	}
	if len(installed.Destinations) != 0 {
		t.Fatalf("installed destinations = %v, want empty", installed.Destinations)
	}
	if device.closeCalls != 1 {
		t.Fatalf("TUN Close calls = %d, want 1", device.closeCalls)
	}
}

func TestRunClientGameRoutesFailClosedWhenPlatformUnsupported(t *testing.T) {
	app := newRouteTestApp(t, []string{"203.0.113.42/24"})
	app.client.selectiveRoutesSupported = func() bool { return false }
	app.client.newTUN = func(tun.Options) (tun.Device, error) {
		t.Fatal("TUN must not be created when selective routes are unsupported")
		return nil, nil
	}
	app.client.installSelectiveRoutes = func(context.Context, tun.SelectiveRouteOptions) (tun.RouteTransaction, error) {
		t.Fatal("route installer must not run when selective routes are unsupported")
		return nil, nil
	}

	err := app.Run(context.Background())
	if !errors.Is(err, tun.ErrSelectiveRoutesUnsupported) {
		t.Fatalf("Run() error = %v, want ErrSelectiveRoutesUnsupported", err)
	}
}

func TestRunClientPassesCanonicalGameRoutePlanAndRollsBack(t *testing.T) {
	app := newRouteTestApp(t, []string{
		" 203.0.113.42/24 ",
		"203.0.113.0/24",
		"2001:db8:1::5/64",
	})
	app.client.selectiveRoutesSupported = func() bool { return true }

	device := &routeTestDevice{name: "Tachyon"}
	app.client.newTUN = func(opts tun.Options) (tun.Device, error) {
		if got, want := opts.Addresses, []netip.Prefix{netip.MustParsePrefix("198.18.0.1/16")}; !reflect.DeepEqual(got, want) {
			t.Fatalf("TUN addresses = %v, want %v", got, want)
		}
		return device, nil
	}
	const interfaceLUID = uint64(0x12345678)
	app.client.stableInterfaceLUID = func(got tun.Device) uint64 {
		if got != device {
			t.Fatalf("LUID device = %T, want route test device", got)
		}
		return interfaceLUID
	}

	txn := &routeTestTransaction{}
	var installed *tun.SelectiveRouteOptions
	app.client.installSelectiveRoutes = func(_ context.Context, opts tun.SelectiveRouteOptions) (tun.RouteTransaction, error) {
		installed = cloneSelectiveRouteOptions(opts)
		return txn, nil
	}
	stopErr := errors.New("PID tracker unavailable")
	app.client.newPIDTracker = func() (*pidtrack.Tracker, error) { return nil, stopErr }

	err := app.Run(context.Background())
	if !errors.Is(err, stopErr) {
		t.Fatalf("Run() error = %v, want %v", err, stopErr)
	}
	if installed == nil {
		t.Fatal("route installer was not called")
	}
	if installed.InterfaceName != "Tachyon" {
		t.Fatalf("interface name = %q, want Tachyon", installed.InterfaceName)
	}
	if installed.InterfaceLUID != interfaceLUID {
		t.Fatalf("interface LUID = %#x, want %#x", installed.InterfaceLUID, interfaceLUID)
	}
	wantRoutes := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:1::/64"),
	}
	if !reflect.DeepEqual(installed.Destinations, wantRoutes) {
		t.Fatalf("installed destinations = %v, want canonical plan %v", installed.Destinations, wantRoutes)
	}
	wantExcluded := []netip.Addr{netip.MustParseAddr("198.51.100.8")}
	if !reflect.DeepEqual(installed.Excluded, wantExcluded) {
		t.Fatalf("excluded relay addresses = %v, want %v", installed.Excluded, wantExcluded)
	}
	if txn.closeCalls != 1 {
		t.Fatalf("route transaction Close calls = %d, want 1", txn.closeCalls)
	}
	if device.closeCalls != 1 {
		t.Fatalf("TUN Close calls = %d, want 1", device.closeCalls)
	}
}

func newRouteTestApp(t *testing.T, gameRoutes []string) *App {
	t.Helper()
	cfg := &config.Config{
		Mode: config.ModeClient,
		Client: config.ClientConfig{
			TUN: config.TUNConfig{
				Name:       "Tachyon",
				Address:    "198.18.0.1/16",
				MTU:        tun.DefaultMTU,
				TGPOnly:    true,
				GameRoutes: gameRoutes,
			},
			Proxy: config.ProxyConfig{ServerAddr: "198.51.100.8:443"},
		},
		TGP: config.TGPConfig{
			FEC: config.FECConfig{DataShards: 1},
			Pacing: config.PacingConfig{
				InitialRatePPS: 1,
			},
			MaxDatagramSize: tgp.DefaultTGPDatagramSize,
		},
	}
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return app
}

func cloneSelectiveRouteOptions(opts tun.SelectiveRouteOptions) *tun.SelectiveRouteOptions {
	opts.Destinations = append([]netip.Prefix(nil), opts.Destinations...)
	opts.Excluded = append([]netip.Addr(nil), opts.Excluded...)
	return &opts
}

type routeTestDevice struct {
	name       string
	closeCalls int
}

func (d *routeTestDevice) Name() string                 { return d.name }
func (*routeTestDevice) Addresses() []netip.Prefix      { return nil }
func (*routeTestDevice) MTU() int                       { return tun.DefaultMTU }
func (*routeTestDevice) ReadPacket([]byte) (int, error) { return 0, errors.New("unexpected TUN read") }
func (*routeTestDevice) WritePacket([]byte) error       { return errors.New("unexpected TUN write") }
func (d *routeTestDevice) Close() error {
	d.closeCalls++
	return nil
}

type routeTestTransaction struct {
	closeCalls int
}

func (t *routeTestTransaction) Close() error {
	t.closeCalls++
	return nil
}
