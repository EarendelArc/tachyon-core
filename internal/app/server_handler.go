package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

type gameUDPRelay interface {
	ForwardUDP(ctx context.Context, packet tgp.RelayPacket, datagram tgp.TunnelDatagram) error
}

type serverRelayHandler struct {
	logger *slog.Logger
	relay  gameUDPRelay
}

func (h serverRelayHandler) HandleRelayPacket(ctx context.Context, packet tgp.RelayPacket) error {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}

	datagram, err := tgp.ParseTunnelDatagram(packet.Payload)
	if err != nil {
		return err
	}
	target := datagram.RemoteAddrPort()
	if h.relay != nil {
		if err := h.relay.ForwardUDP(ctx, packet, datagram); err != nil {
			return err
		}
	}
	logger.Debug("TGP relay forwarded UDP payload",
		"session", packet.SessionID,
		"target", target,
		"bytes", len(datagram.Payload),
	)
	return nil
}

type udpRelayPool struct {
	logger      *slog.Logger
	dialTimeout time.Duration
	idleTimeout time.Duration
	sendTimeout time.Duration

	mu     sync.Mutex
	flows  map[udpRelayKey]*udpRelayFlow
	closed bool
}

type udpRelayKey struct {
	sessionID tgp.SessionID
	local     netip.AddrPort
	remote    netip.AddrPort
}

type udpRelayFlow struct {
	pool        *udpRelayPool
	key         udpRelayKey
	conn        net.Conn
	session     tgp.Session
	idleTimeout time.Duration
	sendTimeout time.Duration
	closeOnce   sync.Once
}

func newUDPRelayPool(logger *slog.Logger, dialTimeout time.Duration, idleTimeout time.Duration) *udpRelayPool {
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	return &udpRelayPool{
		logger:      logger,
		dialTimeout: dialTimeout,
		idleTimeout: idleTimeout,
		sendTimeout: dialTimeout,
		flows:       make(map[udpRelayKey]*udpRelayFlow),
	}
}

func (p *udpRelayPool) ForwardUDP(ctx context.Context, packet tgp.RelayPacket, datagram tgp.TunnelDatagram) error {
	if packet.Session == nil {
		return errors.New("tgp relay packet has no session")
	}
	key := udpRelayKey{
		sessionID: packet.SessionID,
		local:     datagram.LocalAddrPort(),
		remote:    datagram.RemoteAddrPort(),
	}
	flow, err := p.flow(ctx, key, packet.Session)
	if err != nil {
		return err
	}
	return flow.write(ctx, datagram.Payload)
}

func (p *udpRelayPool) flow(ctx context.Context, key udpRelayKey, session tgp.Session) (*udpRelayFlow, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("udp relay pool is closed")
	}
	if flow := p.flows[key]; flow != nil {
		p.mu.Unlock()
		return flow, nil
	}
	p.mu.Unlock()

	dialCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		dialCtx, cancel = context.WithTimeout(ctx, p.dialTimeout)
	}
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", key.remote.String())
	if err != nil {
		return nil, fmt.Errorf("dial game udp %s: %w", key.remote, err)
	}
	created := &udpRelayFlow{
		pool:        p,
		key:         key,
		conn:        conn,
		session:     session,
		idleTimeout: p.idleTimeout,
		sendTimeout: p.sendTimeout,
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = created.close()
		return nil, errors.New("udp relay pool is closed")
	}
	if existing := p.flows[key]; existing != nil {
		_ = created.close()
		return existing, nil
	}
	p.flows[key] = created
	go created.readLoop()
	return created, nil
}

func (p *udpRelayPool) remove(key udpRelayKey, flow *udpRelayFlow) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.flows[key] == flow {
		delete(p.flows, key)
	}
}

func (p *udpRelayPool) Close() error {
	p.mu.Lock()
	flows := make([]*udpRelayFlow, 0, len(p.flows))
	for _, flow := range p.flows {
		flows = append(flows, flow)
	}
	p.flows = make(map[udpRelayKey]*udpRelayFlow)
	p.closed = true
	p.mu.Unlock()

	for _, flow := range flows {
		_ = flow.close()
	}
	return nil
}

func (f *udpRelayFlow) write(ctx context.Context, payload []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = f.conn.SetWriteDeadline(deadline)
	} else if f.sendTimeout > 0 {
		_ = f.conn.SetWriteDeadline(time.Now().Add(f.sendTimeout))
	}
	if _, err := f.conn.Write(payload); err != nil {
		return fmt.Errorf("write game udp %s: %w", f.key.remote, err)
	}
	return nil
}

func (f *udpRelayFlow) readLoop() {
	defer func() {
		f.pool.remove(f.key, f)
		_ = f.close()
	}()

	buf := make([]byte, 65535)
	for {
		if f.idleTimeout > 0 {
			_ = f.conn.SetReadDeadline(time.Now().Add(f.idleTimeout))
		}
		n, err := f.conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return
			}
			if f.pool.logger != nil {
				f.pool.logger.Debug("UDP relay read loop ended", "target", f.key.remote, "error", err)
			}
			return
		}
		if n == 0 {
			continue
		}
		if err := f.sendResponse(buf[:n]); err != nil {
			if f.pool.logger != nil {
				f.pool.logger.Debug("UDP relay response send failed", "target", f.key.remote, "error", err)
			}
			return
		}
	}
}

func (f *udpRelayFlow) sendResponse(payload []byte) error {
	responsePayload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    f.key.local.Addr(),
		LocalPort:  f.key.local.Port(),
		RemoteIP:   f.key.remote.Addr(),
		RemotePort: f.key.remote.Port(),
		Payload:    append([]byte(nil), payload...),
	})
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(context.Background(), f.sendTimeout)
	defer cancel()
	return f.session.SendPacket(sendCtx, capturedPacketStream, responsePayload)
}

func (f *udpRelayFlow) close() error {
	var err error
	f.closeOnce.Do(func() {
		err = f.conn.Close()
	})
	return err
}
