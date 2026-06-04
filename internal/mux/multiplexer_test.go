package mux

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHandleTCPForwardsTLSClientHelloToXray(t *testing.T) {
	backend := newFakeBackend("xray")
	m := New("unused", "unused", backend, nil)

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		m.handleTCP(context.Background(), server)
		close(done)
	}()

	if _, err := client.Write([]byte{0x16}); err != nil {
		t.Fatalf("write client hello: %v", err)
	}

	select {
	case <-backend.tcpCh:
	case <-time.After(time.Second):
		t.Fatal("xray backend did not receive tcp connection")
	}
	if string(backend.peek) != string([]byte{0x16}) {
		t.Fatalf("unexpected peek: %x", backend.peek)
	}
	if stats := m.Snapshot(); stats.XrayConns != 1 || stats.Dropped != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	_ = client.Close()
	<-done
}

func TestHandleTCPDropsUnknownTraffic(t *testing.T) {
	backend := newFakeBackend("xray")
	m := New("unused", "unused", backend, nil)

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		m.handleTCP(context.Background(), server)
		close(done)
	}()

	if _, err := client.Write([]byte{0x01}); err != nil {
		t.Fatalf("write unknown traffic: %v", err)
	}
	select {
	case <-backend.tcpCh:
		t.Fatal("unexpected tcp backend call")
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
	if stats := m.Snapshot(); stats.Dropped != 1 || stats.XrayConns != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestHandleUDPForwardsDTLSToTGP(t *testing.T) {
	backend := newFakeBackend("tgp")
	m := New("unused", "unused", nil, backend)
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	payload := []byte{0x17, 0xfe, 0xff, 0, 1}
	m.handleUDP(context.Background(), payload, from)

	select {
	case got := <-backend.udpCh:
		if string(got.payload) != string(payload) {
			t.Fatalf("unexpected payload: %x", got.payload)
		}
		if got.from.String() != from.String() {
			t.Fatalf("unexpected source: %s", got.from)
		}
	case <-time.After(time.Second):
		t.Fatal("tgp backend did not receive udp packet")
	}
	if stats := m.Snapshot(); stats.TGPPackets != 1 || stats.TGPBytes != uint64(len(payload)) || stats.Dropped != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestHandleUDPDropsUnknownTraffic(t *testing.T) {
	backend := newFakeBackend("tgp")
	m := New("unused", "unused", nil, backend)
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	m.handleUDP(context.Background(), []byte{0x00, 0x01}, from)

	select {
	case <-backend.udpCh:
		t.Fatal("unexpected udp backend call")
	default:
	}
	if stats := m.Snapshot(); stats.Dropped != 1 || stats.TGPPackets != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

type fakeBackend struct {
	name  string
	peek  []byte
	tcpCh chan struct{}
	udpCh chan udpCall
}

type udpCall struct {
	payload []byte
	from    net.Addr
}

func newFakeBackend(name string) *fakeBackend {
	return &fakeBackend{
		name:  name,
		tcpCh: make(chan struct{}, 1),
		udpCh: make(chan udpCall, 1),
	}
}

func (b *fakeBackend) Name() string { return b.name }

func (b *fakeBackend) ForwardTCP(_ context.Context, conn net.Conn, peek []byte) error {
	b.peek = append([]byte(nil), peek...)
	_ = conn.Close()
	b.tcpCh <- struct{}{}
	return nil
}

func (b *fakeBackend) ForwardUDP(_ context.Context, payload []byte, from net.Addr) error {
	b.udpCh <- udpCall{
		payload: append([]byte(nil), payload...),
		from:    from,
	}
	return nil
}
