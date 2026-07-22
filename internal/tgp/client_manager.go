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

var ErrClientManagerClosed = errors.New("tgp client manager closed")

type DialFunc func(ctx context.Context, localAddr string, remoteAddr net.Addr, pacerPPS float64) (Session, error)
type MultipathDialFunc func(ctx context.Context, localAddrs []string, remoteAddr net.Addr, pacerPPS float64) (Session, error)

type ClientManagerOptions struct {
	RemoteAddr       string
	PinnedRemotes    []net.Addr
	LocalAddr        string
	LocalAddrs       []string
	PacerPPS         float64
	FEC              FECOptions
	MaxDatagramSize  int
	DisableMigration bool
	AuthKey          []byte
	HandshakeTimeout time.Duration
	Dial             DialFunc
	DialMultipath    MultipathDialFunc
	ValidateRemote   func(net.Addr) error
	OnDatagram       func(ctx context.Context, datagram TunnelDatagram) error
}

type ClientManager struct {
	remoteAddr       string
	pinnedRemotes    []net.Addr
	localAddr        string
	localAddrs       []string
	pacerPPS         float64
	fec              FECOptions
	handshakeTimeout time.Duration
	dial             DialFunc
	dialMultipath    MultipathDialFunc
	validateRemote   func(net.Addr) error
	onDatagram       func(ctx context.Context, datagram TunnelDatagram) error

	mu         sync.Mutex
	session    Session
	ctx        context.Context
	cancel     context.CancelFunc
	closed     bool
	dialing    bool
	dialDone   chan struct{}
	dialCancel context.CancelFunc
	closeOnce  sync.Once
	closeErr   error
	readWG     sync.WaitGroup
}

func NewClientManager(opts ClientManagerOptions) (*ClientManager, error) {
	if err := validateFECOptions(opts.FEC); err != nil {
		return nil, err
	}
	if _, err := normalizeMaxDatagramSize(opts.MaxDatagramSize); err != nil {
		return nil, err
	}
	remote := strings.TrimSpace(opts.RemoteAddr)
	if remote == "" && len(opts.PinnedRemotes) == 0 {
		return nil, errors.New("tgp remote address is required")
	}
	pinnedRemotes := append([]net.Addr(nil), opts.PinnedRemotes...)
	for idx, pinned := range pinnedRemotes {
		if pinned == nil {
			return nil, fmt.Errorf("pinned tgp remote %d is nil", idx)
		}
		if opts.ValidateRemote != nil {
			if err := opts.ValidateRemote(pinned); err != nil {
				return nil, fmt.Errorf("validate pinned tgp remote %s: %w", pinned, err)
			}
		}
	}
	local := strings.TrimSpace(opts.LocalAddr)
	if local == "" {
		local = "0.0.0.0:0"
	}
	localAddrs := normalizeLocalAddrs(opts.LocalAddrs, local)
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	if timeout > MaxHandshakeTimeout {
		return nil, fmt.Errorf("tgp handshake timeout %s exceeds maximum %s", timeout, MaxHandshakeTimeout)
	}
	dial := opts.Dial
	if dial == nil {
		fec := opts.FEC
		disableMigration := opts.DisableMigration
		authKey := append([]byte(nil), opts.AuthKey...)
		dial = func(ctx context.Context, localAddr string, remoteAddr net.Addr, pacerPPS float64) (Session, error) {
			return DialSessionWithOptions(ctx, localAddr, remoteAddr, SessionRuntimeOptions{
				PacerPPS:         pacerPPS,
				FEC:              fec,
				MaxDatagramSize:  opts.MaxDatagramSize,
				DisableMigration: disableMigration,
				AuthKey:          authKey,
				ValidateRemote:   opts.ValidateRemote,
			})
		}
	}
	dialMultipath := opts.DialMultipath
	if dialMultipath == nil {
		fec := opts.FEC
		disableMigration := opts.DisableMigration
		authKey := append([]byte(nil), opts.AuthKey...)
		dialMultipath = func(ctx context.Context, localAddrs []string, remoteAddr net.Addr, pacerPPS float64) (Session, error) {
			return DialSessionMultipathWithOptions(ctx, localAddrs, remoteAddr, SessionRuntimeOptions{
				PacerPPS:         pacerPPS,
				FEC:              fec,
				MaxDatagramSize:  opts.MaxDatagramSize,
				DisableMigration: disableMigration,
				AuthKey:          authKey,
				ValidateRemote:   opts.ValidateRemote,
			})
		}
	}
	managerCtx, cancel := context.WithCancel(context.Background())
	return &ClientManager{
		remoteAddr:       remote,
		pinnedRemotes:    pinnedRemotes,
		localAddr:        local,
		localAddrs:       localAddrs,
		pacerPPS:         opts.PacerPPS,
		fec:              opts.FEC,
		handshakeTimeout: timeout,
		dial:             dial,
		dialMultipath:    dialMultipath,
		validateRemote:   opts.ValidateRemote,
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
		_ = session.Close()
		return err
	}
	return nil
}

func (m *ClientManager) EnsureSession(ctx context.Context) error {
	_, err := m.sessionFor(ctx)
	return err
}

func (m *ClientManager) Close() error {
	m.closeOnce.Do(func() {
		m.cancel()
		m.mu.Lock()
		m.closed = true
		if m.dialCancel != nil {
			m.dialCancel()
		}
		dialDone := m.dialDone
		session := m.session
		m.session = nil
		m.mu.Unlock()

		if dialDone != nil {
			<-dialDone
		}
		if session != nil {
			m.closeErr = session.Close()
		}
		m.readWG.Wait()
	})
	return m.closeErr
}

func (m *ClientManager) sessionFor(ctx context.Context) (Session, error) {
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrClientManagerClosed
		}
		if m.session != nil && m.session.State() != SessionClosed {
			session := m.session
			m.mu.Unlock()
			return session, nil
		}
		if m.dialing {
			done := m.dialDone
			m.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-m.ctx.Done():
				return nil, ErrClientManagerClosed
			}
		}

		dialCtx, cancel := context.WithTimeout(ctx, m.handshakeTimeout)
		stopManager := context.AfterFunc(m.ctx, cancel)
		done := make(chan struct{})
		m.dialing = true
		m.dialDone = done
		m.dialCancel = cancel
		m.mu.Unlock()

		session, remoteAddr, err := m.dialSession(dialCtx)
		stopManager()
		cancel()

		m.mu.Lock()
		m.dialing = false
		m.dialDone = nil
		m.dialCancel = nil
		if m.closed {
			m.mu.Unlock()
			if session != nil {
				_ = session.Close()
			}
			close(done)
			return nil, ErrClientManagerClosed
		}
		if err != nil {
			m.mu.Unlock()
			close(done)
			return nil, fmt.Errorf("dial tgp session %s: %w", remoteAddr, err)
		}
		m.session = session
		startReadLoop := m.onDatagram != nil
		if startReadLoop {
			m.readWG.Add(1)
		}
		m.mu.Unlock()
		close(done)
		if startReadLoop {
			go func() {
				defer m.readWG.Done()
				m.readLoop(session)
			}()
		}
		return session, nil
	}
}

func (m *ClientManager) dialSession(ctx context.Context) (Session, net.Addr, error) {
	var remoteAddr net.Addr
	var err error
	if len(m.pinnedRemotes) > 0 {
		remoteAddr = m.pinnedRemotes[0]
	} else {
		remoteAddr, err = resolveUDPAddrContext(ctx, m.remoteAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve tgp remote %q: %w", m.remoteAddr, err)
		}
	}
	if m.validateRemote != nil {
		if err := m.validateRemote(remoteAddr); err != nil {
			return nil, remoteAddr, fmt.Errorf("validate tgp remote %s: %w", remoteAddr, err)
		}
	}
	if len(m.localAddrs) > 1 {
		session, err := m.dialMultipath(ctx, m.localAddrs, remoteAddr, m.pacerPPS)
		return session, remoteAddr, err
	}
	localAddr := m.localAddr
	if len(m.localAddrs) == 1 {
		localAddr = m.localAddrs[0]
	}
	session, err := m.dial(ctx, localAddr, remoteAddr, m.pacerPPS)
	return session, remoteAddr, err
}

func resolveUDPAddrContext(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("udp", portText)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.UDPAddr{Port: port}, nil
	}
	if parsed := net.ParseIP(host); parsed != nil {
		return &net.UDPAddr{IP: parsed, Port: port}, nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("resolver returned no addresses")
	}
	return &net.UDPAddr{IP: addresses[0].IP, Port: port, Zone: addresses[0].Zone}, nil
}

func normalizeLocalAddrs(addrs []string, fallback string) []string {
	normalized := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		value := strings.TrimSpace(addr)
		if value != "" {
			normalized = append(normalized, value)
		}
	}
	if len(normalized) == 0 {
		return []string{fallback}
	}
	return normalized
}

func (m *ClientManager) resetSession(session Session) {
	m.mu.Lock()
	if m.session == session {
		m.session = nil
	}
	m.mu.Unlock()
}

func (m *ClientManager) readLoop(session Session) {
	defer func() {
		m.resetSession(session)
		_ = session.Close()
	}()
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
