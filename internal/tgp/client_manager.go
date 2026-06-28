package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const defaultHandshakeTimeout = 5 * time.Second

type DialFunc func(ctx context.Context, localAddr string, remoteAddr net.Addr, pacerPPS float64) (Session, error)

type ClientManagerOptions struct {
	RemoteAddr       string
	LocalAddr        string
	PacerPPS         float64
	HandshakeTimeout time.Duration
	Dial             DialFunc
	OnDatagram       func(ctx context.Context, datagram TunnelDatagram) error
}

type ClientManager struct {
	remoteAddr       string
	localAddr        string
	pacerPPS         float64
	handshakeTimeout time.Duration
	dial             DialFunc
	onDatagram       func(ctx context.Context, datagram TunnelDatagram) error

	mu      sync.Mutex
	session Session
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewClientManager(opts ClientManagerOptions) (*ClientManager, error) {
	remote := strings.TrimSpace(opts.RemoteAddr)
	if remote == "" {
		return nil, errors.New("tgp remote address is required")
	}
	local := strings.TrimSpace(opts.LocalAddr)
	if local == "" {
		local = "0.0.0.0:0"
	}
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	dial := opts.Dial
	if dial == nil {
		dial = func(ctx context.Context, localAddr string, remoteAddr net.Addr, pacerPPS float64) (Session, error) {
			return DialSession(ctx, localAddr, remoteAddr, pacerPPS)
		}
	}
	managerCtx, cancel := context.WithCancel(context.Background())
	return &ClientManager{
		remoteAddr:       remote,
		localAddr:        local,
		pacerPPS:         opts.PacerPPS,
		handshakeTimeout: timeout,
		dial:             dial,
		onDatagram:       opts.OnDatagram,
		ctx:              managerCtx,
		cancel:           cancel,
	}, nil
}

func (m *ClientManager) SendPacket(ctx context.Context, streamID StreamID, payload []byte) error {
	session, err := m.sessionFor(ctx)
	if err != nil {
		return err
	}
	if err := session.SendPacket(ctx, streamID, payload); err != nil {
		m.resetSession(session)
		return err
	}
	return nil
}

func (m *ClientManager) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Lock()
	session := m.session
	m.session = nil
	m.mu.Unlock()
	if session == nil {
		return nil
	}
	return session.Close()
}

func (m *ClientManager) sessionFor(ctx context.Context) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.session != nil && m.session.State() != SessionClosed {
		return m.session, nil
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", m.remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve tgp remote %q: %w", m.remoteAddr, err)
	}
	dialCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		dialCtx, cancel = context.WithTimeout(ctx, m.handshakeTimeout)
	}
	defer cancel()

	session, err := m.dial(dialCtx, m.localAddr, remoteAddr, m.pacerPPS)
	if err != nil {
		return nil, fmt.Errorf("dial tgp session %s: %w", remoteAddr, err)
	}
	m.session = session
	if m.onDatagram != nil {
		go m.readLoop(session)
	}
	return session, nil
}

func (m *ClientManager) resetSession(session Session) {
	m.mu.Lock()
	if m.session == session {
		m.session = nil
	}
	m.mu.Unlock()
}

func (m *ClientManager) readLoop(session Session) {
	for {
		payload, err := session.RecvPacket(m.ctx, capturedPacketStreamID)
		if err != nil {
			return
		}
		datagram, err := ParseTunnelDatagram(payload)
		if err != nil {
			continue
		}
		if err := m.onDatagram(m.ctx, datagram); err != nil {
			continue
		}
	}
}

// ActiveSessions returns 1 if a TGP session is currently active, 0 otherwise.
// Satisfies the observability.SessionCounter interface.
func (m *ClientManager) ActiveSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session != nil && m.session.State() != SessionClosed {
		return 1
	}
	return 0
}

func (m *ClientManager) SessionBytesSent() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session == nil {
		return 0
	}
	return m.session.Stats().BytesSent
}

func (m *ClientManager) SessionBytesReceived() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session == nil {
		return 0
	}
	return m.session.Stats().BytesReceived
}
