// Package mux implements the front-end port multiplexer for server mode.
//
// When tachyon-core runs as a server, it listens on port 443 and dispatches
// incoming connections to the appropriate backend based on traffic fingerprinting:
//
//	TCP + first-byte 0x16 (TLS ClientHello)  → Xray backend (VLESS+Reality)
//	UDP + DTLS 1.0 fingerprint               → TGP relay
//	Unknown                                  → drop
//
// This approach allows a single port to serve both proxy and game traffic,
// making the server appear as a single TLS endpoint to censorship systems.
package mux

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

// TrafficClass indicates how a connection was classified.
type TrafficClass int

const (
	TrafficUnknown TrafficClass = iota
	TrafficXray                 // TLS → forward to local Xray
	TrafficTGP                  // DTLS-disguised TGP → forward to TGP relay
)

func (c TrafficClass) String() string {
	switch c {
	case TrafficXray:
		return "xray"
	case TrafficTGP:
		return "tgp"
	default:
		return "unknown"
	}
}

// Stats holds per-class packet/byte counters.
type Stats struct {
	XrayConns   atomic.Uint64
	XrayBytes   atomic.Uint64
	TGPPackets  atomic.Uint64
	TGPBytes    atomic.Uint64
	Dropped     atomic.Uint64
}

// Snapshot returns a point-in-time copy of the counters.
type StatsSnapshot struct {
	XrayConns  uint64
	XrayBytes  uint64
	TGPPackets uint64
	TGPBytes   uint64
	Dropped    uint64
}

// Backend receives a classified flow for further processing.
type Backend interface {
	// ForwardTCP splices conn to the backend. peek contains bytes already read
	// from conn during fingerprinting.
	ForwardTCP(ctx context.Context, conn net.Conn, peek []byte) error

	// ForwardUDP sends a single datagram to the backend.
	ForwardUDP(ctx context.Context, payload []byte, from net.Addr) error

	// Name returns a human-readable identifier.
	Name() string
}

// Mux is the top-level traffic dispatcher.
type Mux struct {
	tcpAddr  string
	udpAddr  string
	xray     Backend
	tgp      Backend
	stats    Stats
}

// New creates a Mux that will listen on tcpAddr (TCP) and udpAddr (UDP).
func New(tcpAddr, udpAddr string, xray, tgp Backend) *Mux {
	return &Mux{
		tcpAddr: tcpAddr,
		udpAddr: udpAddr,
		xray:    xray,
		tgp:     tgp,
	}
}

// ListenAndServe starts both TCP and UDP listeners and blocks until ctx is done.
func (m *Mux) ListenAndServe(ctx context.Context) error {
	tcpErr := make(chan error, 1)
	udpErr := make(chan error, 1)

	go func() { tcpErr <- m.serveTCP(ctx) }()
	go func() { udpErr <- m.serveUDP(ctx) }()

	select {
	case err := <-tcpErr:
		return fmt.Errorf("tcp listener: %w", err)
	case err := <-udpErr:
		return fmt.Errorf("udp listener: %w", err)
	case <-ctx.Done():
		return nil
	}
}

// Snapshot returns current traffic counters.
func (m *Mux) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		XrayConns:  m.stats.XrayConns.Load(),
		XrayBytes:  m.stats.XrayBytes.Load(),
		TGPPackets: m.stats.TGPPackets.Load(),
		TGPBytes:   m.stats.TGPBytes.Load(),
		Dropped:    m.stats.Dropped.Load(),
	}
}

// ---------------------------------------------------------------------------
// TCP path
// ---------------------------------------------------------------------------

func (m *Mux) serveTCP(ctx context.Context) error {
	ln, err := net.Listen("tcp", m.tcpAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go m.handleTCP(ctx, conn)
	}
}

func (m *Mux) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Peek at first byte to classify without consuming it.
	var peek [1]byte
	n, err := conn.Read(peek[:])
	if err != nil || n == 0 {
		m.stats.Dropped.Add(1)
		return
	}

	// 0x16 = TLS ContentType handshake (ClientHello)
	if peek[0] == 0x16 {
		m.stats.XrayConns.Add(1)
		if m.xray != nil {
			_ = m.xray.ForwardTCP(ctx, conn, peek[:1])
		}
		return
	}

	// Unknown protocol — drop silently.
	m.stats.Dropped.Add(1)
}

// ---------------------------------------------------------------------------
// UDP path
// ---------------------------------------------------------------------------

func (m *Mux) serveUDP(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", m.udpAddr)
	if err != nil {
		return err
	}
	defer pc.Close()

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go m.handleUDP(ctx, pkt, from)
	}
}

func (m *Mux) handleUDP(ctx context.Context, payload []byte, from net.Addr) {
	if !isTGPPacket(payload) {
		m.stats.Dropped.Add(1)
		return
	}

	m.stats.TGPPackets.Add(1)
	m.stats.TGPBytes.Add(uint64(len(payload)))

	if m.tgp != nil {
		_ = m.tgp.ForwardUDP(ctx, payload, from)
	}
}

// isTGPPacket returns true if the UDP payload matches the TGP/DTLS fingerprint:
//
//	byte[0] == 0x17  (ContentType: application_data)
//	byte[1] == 0xFE  (Version major: DTLS 1.0)
//	byte[2] == 0xFF  (Version minor: DTLS 1.0)
func isTGPPacket(payload []byte) bool {
	return len(payload) >= 3 &&
		payload[0] == 0x17 &&
		payload[1] == 0xFE &&
		payload[2] == 0xFF
}

// ---------------------------------------------------------------------------
// XrayBackend: TCP splice to a local Xray process
// ---------------------------------------------------------------------------

// XrayBackend forwards TCP connections to a locally running Xray instance.
type XrayBackend struct {
	Addr string // e.g. "127.0.0.1:18443"
}

func (b *XrayBackend) Name() string { return "xray@" + b.Addr }

func (b *XrayBackend) ForwardTCP(ctx context.Context, conn net.Conn, peek []byte) error {
	up, err := (&net.Dialer{}).DialContext(ctx, "tcp", b.Addr)
	if err != nil {
		return fmt.Errorf("dial xray backend %s: %w", b.Addr, err)
	}
	// Re-inject the peeked byte before splicing.
	if len(peek) > 0 {
		if _, err := up.Write(peek); err != nil {
			_ = up.Close()
			return err
		}
	}
	go spliceHalf(conn, up)
	go spliceHalf(up, conn)
	return nil
}

func (b *XrayBackend) ForwardUDP(_ context.Context, _ []byte, _ net.Addr) error {
	return nil // Xray doesn't receive UDP from the mux
}

func spliceHalf(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	_, _ = io.CopyBuffer(dst, src, buf)
	_ = dst.Close()
}
