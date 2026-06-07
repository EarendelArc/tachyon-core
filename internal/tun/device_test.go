package tun

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
)

// fakeDevice implements a simple in-memory TUN for testing.
type fakeDevice struct {
	name  string
	addrs []netip.Prefix
	mtu   int

	mu      sync.Mutex
	buf     []byte
	readErr error
	closed  bool
}

func (f *fakeDevice) Name() string              { return f.name }
func (f *fakeDevice) Addresses() []netip.Prefix { return append([]netip.Prefix(nil), f.addrs...) }
func (f *fakeDevice) MTU() int                  { return f.mtu }

func (f *fakeDevice) ReadPacket(buf []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return 0, os.ErrClosed
	}
	if f.readErr != nil {
		return 0, f.readErr
	}
	if f.buf == nil {
		return 0, nil
	}
	return copy(buf, f.buf), nil
}

func (f *fakeDevice) WritePacket(buf []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return os.ErrClosed
	}
	f.buf = append([]byte(nil), buf...)
	return nil
}

func (f *fakeDevice) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return errors.New("already closed")
	}
	f.closed = true
	return nil
}

func newFakeDevice(addrs []string) *fakeDevice {
	prefixes := make([]netip.Prefix, len(addrs))
	for i, a := range addrs {
		prefixes[i] = netip.MustParsePrefix(a)
	}
	return &fakeDevice{
		name:  "tachyon0",
		addrs: prefixes,
		mtu:   DefaultMTU,
	}
}

var _ Device = (*fakeDevice)(nil)

func TestOptions_MTU_default(t *testing.T) {
	o := Options{MTU: 0}
	if o.mtu() != DefaultMTU {
		t.Errorf("expected default MTU %d, got %d", DefaultMTU, o.mtu())
	}
	o.MTU = 1500
	if o.mtu() != 1500 {
		t.Errorf("expected custom MTU 1500, got %d", o.mtu())
	}
}

func TestFakeDevice_Name(t *testing.T) {
	d := newFakeDevice([]string{"198.18.0.1/16"})
	if d.Name() != "tachyon0" {
		t.Errorf("expected name tachyon0, got %s", d.Name())
	}
}

func TestFakeDevice_Addresses(t *testing.T) {
	d := newFakeDevice([]string{"198.18.0.1/16", "fc00::1/64"})
	addrs := d.Addresses()
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
	if addrs[0].String() != "198.18.0.1/16" {
		t.Errorf("expected 198.18.0.1/16, got %s", addrs[0])
	}
	if addrs[1].String() != "fc00::1/64" {
		t.Errorf("expected fc00::1/64, got %s", addrs[1])
	}
}

func TestFakeDevice_WritePacketThenReadPacket(t *testing.T) {
	d := newFakeDevice([]string{"198.18.0.1/16"})
	pkt := make([]byte, 64)
	pkt[0] = 0x45 // IPv4

	if err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	buf := make([]byte, 128)
	n, err := d.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if n != len(pkt) {
		t.Errorf("expected %d bytes, got %d", len(pkt), n)
	}
	if buf[0] != 0x45 {
		t.Error("packet corruption: first byte not 0x45")
	}
}

func TestFakeDevice_Close(t *testing.T) {
	d := newFakeDevice([]string{"198.18.0.1/16"})

	if err := d.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := d.Close(); err == nil {
		t.Error("expected error on second close")
	}
	if _, err := d.ReadPacket(make([]byte, 128)); !errors.Is(err, os.ErrClosed) {
		t.Errorf("expected ErrClosed on read after close, got %v", err)
	}
	if err := d.WritePacket([]byte{0}); !errors.Is(err, os.ErrClosed) {
		t.Errorf("expected ErrClosed on write after close, got %v", err)
	}
}

func TestFakeDevice_ReadBeforeWrite(t *testing.T) {
	d := newFakeDevice([]string{"198.18.0.1/16"})
	buf := make([]byte, 128)
	n, err := d.ReadPacket(buf)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes before write, got %d", n)
	}
}
