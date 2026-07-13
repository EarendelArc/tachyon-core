package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultRelayMaxSessions        = 1024
	defaultRelaySessionQueueSize   = 256
	defaultRelayHandlerConcurrency = 1024
	defaultRelayHandshakeQueueSize = 64
	defaultRelayMaxPathsPerSession = 8
	defaultRelayMaxPendingPaths    = 4096
	pathChallengeLifetime          = 5 * time.Second
)

var ErrRelayResourceLimit = errors.New("tgp relay resource limit reached")

type RelayPacket struct {
	SessionID SessionID
	Session   Session
	Payload   []byte
}

type RelayHandler interface {
	HandleRelayPacket(ctx context.Context, packet RelayPacket) error
}

type RelayHandlerFunc func(ctx context.Context, packet RelayPacket) error

func (f RelayHandlerFunc) HandleRelayPacket(ctx context.Context, packet RelayPacket) error {
	return f(ctx, packet)
}

type RelayOptions struct {
	ListenAddr         string
	Transport          Transport
	PacerPPS           float64
	FEC                FECOptions
	DisableMigration   bool
	AuthKey            []byte
	SessionIdleTimeout time.Duration
	MaxSessions        int
	SessionQueueSize   int
	HandlerConcurrency int
	HandshakeQueueSize int
	Handler            RelayHandler
}

type Relay struct {
	listenAddr         string
	pacerPPS           float64
	fec                FECOptions
	disableMigration   bool
	authKey            []byte
	sessionIdleTimeout time.Duration
	maxSessions        int
	sessionQueueSize   int
	handlerConcurrency int
	handshakeQueueSize int
	handler            RelayHandler
	handlerTokens      chan struct{}

	mu        sync.Mutex
	transport Transport
	router    *relayTransportRouter
	sessions  map[SessionID]Session
	closed    bool
}

func NewRelay(opts RelayOptions) (*Relay, error) {
	if opts.Transport == nil && opts.ListenAddr == "" {
		return nil, errors.New("relay listen address or transport is required")
	}
	handler := opts.Handler
	if handler == nil {
		handler = RelayHandlerFunc(func(context.Context, RelayPacket) error { return nil })
	}
	maxSessions := defaultRelayMaxSessions
	if opts.MaxSessions > 0 {
		maxSessions = opts.MaxSessions
	}
	sessionQueueSize := defaultRelaySessionQueueSize
	if opts.SessionQueueSize > 0 {
		sessionQueueSize = opts.SessionQueueSize
	}
	handlerConcurrency := defaultRelayHandlerConcurrency
	if opts.HandlerConcurrency > 0 {
		handlerConcurrency = opts.HandlerConcurrency
	}
	handshakeQueueSize := defaultRelayHandshakeQueueSize
	if opts.HandshakeQueueSize > 0 {
		handshakeQueueSize = opts.HandshakeQueueSize
	}
	return &Relay{
		listenAddr:         opts.ListenAddr,
		pacerPPS:           opts.PacerPPS,
		fec:                opts.FEC,
		disableMigration:   opts.DisableMigration,
		authKey:            append([]byte(nil), opts.AuthKey...),
		sessionIdleTimeout: opts.SessionIdleTimeout,
		maxSessions:        maxSessions,
		sessionQueueSize:   sessionQueueSize,
		handlerConcurrency: handlerConcurrency,
		handshakeQueueSize: handshakeQueueSize,
		handler:            handler,
		handlerTokens:      make(chan struct{}, handlerConcurrency),
		transport:          opts.Transport,
		sessions:           make(map[SessionID]Session),
	}, nil
}

func (r *Relay) ListenAndServe(ctx context.Context) error {
	transport := r.transport
	if transport == nil {
		udpTransport, err := ListenUDP(r.listenAddr)
		if err != nil {
			return err
		}
		transport = udpTransport
		r.setTransport(transport)
	}

	router := newRelayTransportRouter(transport, r.sessionQueueSize, r.handshakeQueueSize)
	r.setRouter(router)
	go router.readLoop(ctx)

	for {
		session, err := r.acceptSession(ctx, router)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ErrSessionClosed) {
				return nil
			}
			return fmt.Errorf("accept tgp session: %w", err)
		}
		if !r.addSession(session) {
			_ = session.Close()
			continue
		}
		go r.serveSession(ctx, session)
	}
}

func (r *Relay) acceptSession(ctx context.Context, router *relayTransportRouter) (*DatagramSession, error) {
	keyPair, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	for {
		envelope, err := router.nextHandshake(ctx)
		if err != nil {
			return nil, err
		}
		msg, err := parseHandshake(envelope.packet)
		if err != nil || msg.msgType != handshakeHello {
			continue
		}
		if err := verifyHandshakeAuth(msg, r.authKey, PublicKey{}); err != nil {
			continue
		}
		if r.hasSession(msg.sessionID) {
			continue
		}
		if !r.canAcceptSession() {
			continue
		}
		keys, err := keyPair.DeriveTrafficKeysWithAuth(msg.publicKey, msg.sessionID, RoleServer, r.authKey)
		if err != nil {
			return nil, err
		}
		pathKey := derivePathAuthKey(keys.RecvKey, msg.sessionID)
		sessionTransport, err := router.registerWithPathAuth(msg.sessionID, envelope.from, pathKey, !r.disableMigration)
		if err != nil {
			return nil, err
		}
		ack, err := marshalHandshake(handshakeHelloAck, msg.sessionID, keyPair.PublicKey(), r.authKey, msg.publicKey)
		if err != nil {
			_ = sessionTransport.Close()
			return nil, err
		}
		if err := sessionTransport.WritePacket(ctx, ack, envelope.from); err != nil {
			_ = sessionTransport.Close()
			return nil, err
		}
		return NewDatagramSession(SessionOptions{
			ID:               msg.sessionID,
			Transport:        sessionTransport,
			RemoteAddr:       envelope.from,
			SendKey:          keys.SendKey,
			RecvKey:          keys.RecvKey,
			Pacer:            NewTokenBucketPacer(r.pacerPPS),
			FEC:              r.fec,
			DisableMigration: r.disableMigration,
		})
	}
}

func (r *Relay) serveSession(ctx context.Context, session Session) {
	defer func() {
		r.removeSession(session.ID(), session)
		_ = session.Close()
	}()

	for {
		recvCtx := ctx
		cancel := func() {}
		if r.sessionIdleTimeout > 0 {
			recvCtx, cancel = context.WithTimeout(ctx, r.sessionIdleTimeout)
		}
		payload, err := session.RecvPacket(recvCtx, capturedPacketStreamID)
		cancel()
		if err != nil {
			return
		}
		packet := RelayPacket{
			SessionID: session.ID(),
			Session:   session,
			Payload:   append([]byte(nil), payload...),
		}
		_ = r.dispatchPacket(ctx, packet)
	}
}

func (r *Relay) dispatchPacket(ctx context.Context, packet RelayPacket) bool {
	select {
	case r.handlerTokens <- struct{}{}:
	default:
		return false
	}
	go func() {
		defer func() { <-r.handlerTokens }()
		_ = r.handler.HandleRelayPacket(ctx, packet)
	}()
	return true
}

func (r *Relay) LocalAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.transport == nil {
		return nil
	}
	return r.transport.LocalAddr()
}

func (r *Relay) Close() error {
	r.mu.Lock()
	sessions := make([]Session, 0, len(r.sessions))
	for _, session := range r.sessions {
		sessions = append(sessions, session)
	}
	transport := r.transport
	router := r.router
	r.sessions = make(map[SessionID]Session)
	r.transport = nil
	r.router = nil
	r.closed = true
	r.mu.Unlock()

	if router != nil {
		router.close()
	}
	for _, session := range sessions {
		_ = session.Close()
	}
	if transport != nil {
		return transport.Close()
	}
	return nil
}

func (r *Relay) setTransport(transport Transport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transport = transport
}

func (r *Relay) setRouter(router *relayTransportRouter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.router = router
}

func (r *Relay) addSession(session Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(r.sessions) >= r.maxSessions {
		return false
	}
	r.sessions[session.ID()] = session
	return true
}

func (r *Relay) removeSession(id SessionID, session Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[id] == session {
		delete(r.sessions, id)
	}
}

func (r *Relay) hasSession(id SessionID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id] != nil
}

func (r *Relay) canAcceptSession() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && len(r.sessions) < r.maxSessions
}

const capturedPacketStreamID StreamID = 0

type relayPacketEnvelope struct {
	packet []byte
	from   net.Addr
}

type sourceAddrKey struct {
	network string
	address string
}

func newSourceAddrKey(addr net.Addr) (sourceAddrKey, bool) {
	if addr == nil {
		return sourceAddrKey{}, false
	}
	network := addr.Network()
	address := addr.String()
	if network == "" || address == "" {
		return sourceAddrKey{}, false
	}
	return sourceAddrKey{network: network, address: address}, true
}

type relayTransportRouter struct {
	transport Transport

	mu                 sync.Mutex
	handshakes         chan relayPacketEnvelope
	done               chan struct{}
	sessions           map[SessionID]*relaySessionTransport
	sources            map[sourceAddrKey]*relaySessionTransport
	pendingPaths       map[pendingPathKey]pendingPathChallenge
	sessionQueueSize   int
	droppedHandshakes  atomic.Uint64
	droppedData        atomic.Uint64
	droppedUnknownData atomic.Uint64
	droppedPathControl atomic.Uint64
	closed             bool
	closeOnce          sync.Once
}

type pendingPathKey struct {
	sessionID SessionID
	source    sourceAddrKey
}

type pendingPathChallenge struct {
	session     *relaySessionTransport
	clientNonce [pathControlNonceSize]byte
	serverNonce [pathControlNonceSize]byte
	expiresAt   time.Time
}

func newRelayTransportRouter(transport Transport, sessionQueueSize int, handshakeQueueSize int) *relayTransportRouter {
	if sessionQueueSize <= 0 {
		sessionQueueSize = defaultRelaySessionQueueSize
	}
	if handshakeQueueSize <= 0 {
		handshakeQueueSize = defaultRelayHandshakeQueueSize
	}
	return &relayTransportRouter{
		transport:        transport,
		handshakes:       make(chan relayPacketEnvelope, handshakeQueueSize),
		done:             make(chan struct{}),
		sessions:         make(map[SessionID]*relaySessionTransport),
		sources:          make(map[sourceAddrKey]*relaySessionTransport),
		pendingPaths:     make(map[pendingPathKey]pendingPathChallenge),
		sessionQueueSize: sessionQueueSize,
	}
}

func (r *relayTransportRouter) readLoop(ctx context.Context) {
	defer r.close()
	for {
		packet, from, err := r.transport.ReadPacket(ctx)
		if err != nil {
			return
		}
		envelope := relayPacketEnvelope{packet: packet, from: from}
		if msg, err := parsePathControl(packet); err == nil {
			r.handlePathControl(ctx, envelope, msg)
			continue
		}
		if msg, err := parseHandshake(packet); err == nil && msg.msgType == handshakeHello {
			select {
			case r.handshakes <- envelope:
			case <-r.done:
				return
			default:
				r.droppedHandshakes.Add(1)
			}
			continue
		}
		r.routeData(envelope)
	}
}

func (r *relayTransportRouter) nextHandshake(ctx context.Context) (relayPacketEnvelope, error) {
	select {
	case envelope, ok := <-r.handshakes:
		if !ok {
			return relayPacketEnvelope{}, ErrSessionClosed
		}
		return envelope, nil
	case <-r.done:
		return relayPacketEnvelope{}, ErrSessionClosed
	case <-ctx.Done():
		return relayPacketEnvelope{}, ctx.Err()
	}
}

func (r *relayTransportRouter) register(id SessionID, addr net.Addr) (*relaySessionTransport, error) {
	return r.registerWithPathAuth(id, addr, [trafficKeySize]byte{}, false)
}

func (r *relayTransportRouter) registerWithPathAuth(id SessionID, addr net.Addr, pathKey [trafficKeySize]byte, allowAdditionalPaths bool) (*relaySessionTransport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrSessionClosed
	}
	if _, ok := r.sessions[id]; ok {
		return nil, ErrInvalidHandshake
	}
	addrKey, ok := newSourceAddrKey(addr)
	if !ok {
		return nil, errors.New("tgp relay session source address is required")
	}
	if _, ok := r.sources[addrKey]; ok {
		return nil, ErrInvalidHandshake
	}
	session := &relaySessionTransport{
		id:                   id,
		router:               r,
		sourceKeys:           map[sourceAddrKey]struct{}{addrKey: {}},
		sourceAddrs:          map[sourceAddrKey]net.Addr{addrKey: addr},
		activeSource:         addrKey,
		pathKey:              pathKey,
		allowAdditionalPaths: allowAdditionalPaths,
		packets:              make(chan relayPacketEnvelope, r.sessionQueueSize),
		done:                 make(chan struct{}),
	}
	r.sessions[id] = session
	r.sources[addrKey] = session
	return session, nil
}

func (r *relayTransportRouter) unregister(id SessionID, session *relaySessionTransport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[id] == session {
		delete(r.sessions, id)
	}
	for source := range session.sourceKeys {
		if r.sources[source] == session {
			delete(r.sources, source)
		}
	}
	for key, pending := range r.pendingPaths {
		if pending.session == session {
			delete(r.pendingPaths, key)
		}
	}
}

func (r *relayTransportRouter) routeData(envelope relayPacketEnvelope) {
	addrKey, ok := newSourceAddrKey(envelope.from)
	if !ok {
		r.droppedUnknownData.Add(1)
		return
	}
	r.mu.Lock()
	session := r.sources[addrKey]
	r.mu.Unlock()

	if session == nil {
		r.droppedUnknownData.Add(1)
		return
	}
	select {
	case session.packets <- envelope:
	default:
		r.droppedData.Add(1)
	}
}

func (r *relayTransportRouter) handlePathControl(ctx context.Context, envelope relayPacketEnvelope, msg pathControlMessage) {
	source, ok := newSourceAddrKey(envelope.from)
	if !ok {
		r.droppedPathControl.Add(1)
		return
	}
	switch msg.msgType {
	case pathControlRequest:
		r.handlePathRequest(ctx, envelope.from, source, msg)
	case pathControlResponse:
		r.handlePathResponse(envelope.from, source, msg)
	default:
		r.droppedPathControl.Add(1)
	}
}

func (r *relayTransportRouter) handlePathRequest(ctx context.Context, from net.Addr, source sourceAddrKey, msg pathControlMessage) {
	r.mu.Lock()
	r.purgeExpiredPathChallengesLocked(time.Now())
	session := r.sessions[msg.sessionID]
	if session == nil || !session.allowAdditionalPaths || session.activeSource == source {
		r.mu.Unlock()
		return
	}
	if owner := r.sources[source]; owner != nil && owner != session {
		r.mu.Unlock()
		r.droppedPathControl.Add(1)
		return
	}
	pathKey := session.pathKey
	r.mu.Unlock()
	if !verifyPathControl(msg, pathKey) {
		r.droppedPathControl.Add(1)
		return
	}

	serverNonce, err := newPathNonce()
	if err != nil {
		r.droppedPathControl.Add(1)
		return
	}
	challenge, err := marshalPathControl(pathControlChallenge, msg.sessionID, msg.clientNonce, serverNonce, pathKey)
	if err != nil {
		r.droppedPathControl.Add(1)
		return
	}

	r.mu.Lock()
	if r.closed || r.sessions[msg.sessionID] != session || len(r.pendingPaths) >= defaultRelayMaxPendingPaths {
		r.mu.Unlock()
		r.droppedPathControl.Add(1)
		return
	}
	r.pendingPaths[pendingPathKey{sessionID: msg.sessionID, source: source}] = pendingPathChallenge{
		session:     session,
		clientNonce: msg.clientNonce,
		serverNonce: serverNonce,
		expiresAt:   time.Now().Add(pathChallengeLifetime),
	}
	r.mu.Unlock()
	if r.transport == nil || r.transport.WritePacket(ctx, challenge, from) != nil {
		r.mu.Lock()
		key := pendingPathKey{sessionID: msg.sessionID, source: source}
		pending, ok := r.pendingPaths[key]
		if ok && pending.session == session && pending.clientNonce == msg.clientNonce && pending.serverNonce == serverNonce {
			delete(r.pendingPaths, key)
		}
		r.mu.Unlock()
		r.droppedPathControl.Add(1)
	}
}

func (r *relayTransportRouter) handlePathResponse(from net.Addr, source sourceAddrKey, msg pathControlMessage) {
	key := pendingPathKey{sessionID: msg.sessionID, source: source}
	r.mu.Lock()
	pending, ok := r.pendingPaths[key]
	if !ok || time.Now().After(pending.expiresAt) || r.sessions[msg.sessionID] != pending.session {
		delete(r.pendingPaths, key)
		r.mu.Unlock()
		r.droppedPathControl.Add(1)
		return
	}
	pathKey := pending.session.pathKey
	r.mu.Unlock()
	if msg.clientNonce != pending.clientNonce || msg.serverNonce != pending.serverNonce || !verifyPathControl(msg, pathKey) {
		r.droppedPathControl.Add(1)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	pending, ok = r.pendingPaths[key]
	if !ok || time.Now().After(pending.expiresAt) || r.sessions[msg.sessionID] != pending.session ||
		msg.clientNonce != pending.clientNonce || msg.serverNonce != pending.serverNonce {
		delete(r.pendingPaths, key)
		r.droppedPathControl.Add(1)
		return
	}
	delete(r.pendingPaths, key)
	if owner := r.sources[source]; owner != nil && owner != pending.session {
		r.droppedPathControl.Add(1)
		return
	}
	_, alreadyAuthorized := pending.session.sourceKeys[source]
	if !alreadyAuthorized && len(pending.session.sourceKeys) >= defaultRelayMaxPathsPerSession {
		r.droppedPathControl.Add(1)
		return
	}
	pending.session.sourceKeys[source] = struct{}{}
	pending.session.sourceAddrs[source] = from
	pending.session.activeSource = source
	r.sources[source] = pending.session
}

func (r *relayTransportRouter) purgeExpiredPathChallengesLocked(now time.Time) {
	for key, pending := range r.pendingPaths {
		if now.After(pending.expiresAt) {
			delete(r.pendingPaths, key)
		}
	}
}

func (r *relayTransportRouter) close() {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		sessions := make([]*relaySessionTransport, 0, len(r.sessions))
		for _, session := range r.sessions {
			sessions = append(sessions, session)
		}
		r.sessions = make(map[SessionID]*relaySessionTransport)
		r.sources = make(map[sourceAddrKey]*relaySessionTransport)
		r.pendingPaths = make(map[pendingPathKey]pendingPathChallenge)
		close(r.done)
		r.mu.Unlock()

		for _, session := range sessions {
			_ = session.Close()
		}
	})
}

type relaySessionTransport struct {
	id                   SessionID
	router               *relayTransportRouter
	sourceKeys           map[sourceAddrKey]struct{}
	sourceAddrs          map[sourceAddrKey]net.Addr
	activeSource         sourceAddrKey
	pathKey              [trafficKeySize]byte
	allowAdditionalPaths bool
	packets              chan relayPacketEnvelope
	done                 chan struct{}
	closeOnce            sync.Once
}

func (t *relaySessionTransport) WritePacket(ctx context.Context, pkt []byte, addr net.Addr) error {
	if t == nil || t.router == nil {
		return ErrSessionClosed
	}
	t.router.mu.Lock()
	transport := t.router.transport
	activeAddr := t.sourceAddrs[t.activeSource]
	t.router.mu.Unlock()
	if transport == nil || activeAddr == nil {
		return ErrSessionClosed
	}
	return transport.WritePacket(ctx, pkt, activeAddr)
}

func (t *relaySessionTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case envelope := <-t.packets:
		return envelope.packet, envelope.from, nil
	case <-t.done:
		return nil, nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (t *relaySessionTransport) LocalAddr() net.Addr {
	return t.router.transport.LocalAddr()
}

func (t *relaySessionTransport) IsSourceAuthorized(addr net.Addr) bool {
	key, ok := newSourceAddrKey(addr)
	if !ok {
		return false
	}
	t.router.mu.Lock()
	defer t.router.mu.Unlock()
	_, ok = t.sourceKeys[key]
	return ok
}

func (t *relaySessionTransport) ManagesReturnPath() bool { return true }

func (t *relaySessionTransport) Close() error {
	t.closeOnce.Do(func() {
		t.router.unregister(t.id, t)
		close(t.done)
	})
	return nil
}
