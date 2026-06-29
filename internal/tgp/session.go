package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

const (
	defaultStreamQueue = 64
	defaultDedupWindow = 4096
)

var (
	ErrSessionClosed     = errors.New("tgp session closed")
	ErrSessionIDMismatch = errors.New("tgp session id mismatch")
)

type SessionOptions struct {
	ID          SessionID
	Transport   Transport
	RemoteAddr  net.Addr
	SendKey     [trafficKeySize]byte
	RecvKey     [trafficKeySize]byte
	Pacer       Pacer
	StreamQueue int
}

type DatagramSession struct {
	id        SessionID
	transport Transport
	sendCodec *Codec
	recvCodec *Codec
	pacer     Pacer

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.RWMutex
	state   SessionState
	remote  net.Addr
	streams map[StreamID]chan []byte
	dedup   *packetDedupWindow

	packetNo atomic.Uint64
	stats    sessionCounters
}

type sessionCounters struct {
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	migrations    atomic.Uint32
}

func NewDatagramSession(opts SessionOptions) (*DatagramSession, error) {
	if opts.Transport == nil {
		return nil, errors.New("tgp session transport is required")
	}
	if opts.RemoteAddr == nil {
		return nil, errors.New("tgp session remote address is required")
	}
	sendCodec, err := NewCodec(opts.SendKey)
	if err != nil {
		return nil, fmt.Errorf("send codec: %w", err)
	}
	recvCodec, err := NewCodec(opts.RecvKey)
	if err != nil {
		return nil, fmt.Errorf("recv codec: %w", err)
	}
	pacer := opts.Pacer
	if pacer == nil {
		pacer = NewTokenBucketPacer(128)
	}
	queueSize := opts.StreamQueue
	if queueSize <= 0 {
		queueSize = defaultStreamQueue
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &DatagramSession{
		id:        opts.ID,
		transport: opts.Transport,
		sendCodec: sendCodec,
		recvCodec: recvCodec,
		pacer:     pacer,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		state:     SessionEstablished,
		remote:    opts.RemoteAddr,
		streams:   make(map[StreamID]chan []byte),
		dedup:     newPacketDedupWindow(defaultDedupWindow),
	}
	s.streams[0] = make(chan []byte, queueSize)

	go s.readLoop(queueSize)
	return s, nil
}

func (s *DatagramSession) ID() SessionID {
	return s.id
}

func (s *DatagramSession) State() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *DatagramSession) SendPacket(ctx context.Context, streamID StreamID, payload []byte) error {
	if s.State() == SessionClosed {
		return ErrSessionClosed
	}
	if err := s.pacer.Consume(ctx); err != nil {
		return err
	}
	packetNo := s.packetNo.Add(1)
	header, err := NewDataHeader(s.id, streamID, packetNo, len(payload))
	if err != nil {
		return err
	}
	wire, err := s.sendCodec.Seal(packetNo, header, payload)
	if err != nil {
		return err
	}

	s.mu.RLock()
	remote := s.remote
	s.mu.RUnlock()
	if err := s.transport.WritePacket(ctx, wire, remote); err != nil {
		return err
	}
	s.stats.bytesSent.Add(uint64(len(payload)))
	return nil
}

func (s *DatagramSession) RecvPacket(ctx context.Context, streamID StreamID) ([]byte, error) {
	ch := s.stream(streamID)
	select {
	case payload := <-ch:
		return payload, nil
	case <-s.done:
		return nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *DatagramSession) Migrate(ctx context.Context, newAddr net.Addr) error {
	if newAddr == nil {
		return errors.New("nil migration address")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == SessionClosed {
		return ErrSessionClosed
	}
	s.state = SessionMigrating
	s.remote = newAddr
	s.state = SessionEstablished
	s.stats.migrations.Add(1)
	return nil
}

func (s *DatagramSession) Close() error {
	s.mu.Lock()
	if s.state == SessionClosed {
		s.mu.Unlock()
		return nil
	}
	s.state = SessionClosed
	s.mu.Unlock()

	s.cancel()
	<-s.done
	return s.transport.Close()
}

func (s *DatagramSession) Stats() SessionStats {
	return SessionStats{
		BytesSent:     s.stats.bytesSent.Load(),
		BytesReceived: s.stats.bytesReceived.Load(),
		Migrations:    s.stats.migrations.Load(),
	}
}

func (s *DatagramSession) readLoop(queueSize int) {
	defer close(s.done)
	for {
		wire, from, err := s.transport.ReadPacket(s.ctx)
		if err != nil {
			return
		}
		packet, err := s.recvCodec.Open(wire)
		if err != nil {
			continue
		}
		if packet.Inner.SessionID != s.id {
			continue
		}
		packet.SourceAddr = from
		s.migrateIfNeeded(from)
		if !s.dedup.SeenFirst(packet.Inner.PacketNumber) {
			continue
		}
		s.stats.bytesReceived.Add(uint64(len(packet.Payload)))
		ch := s.streamWithSize(packet.Inner.StreamID, queueSize)
		select {
		case ch <- packet.Payload:
		default:
			// Prefer dropping a stale game datagram over adding queue latency.
		}
	}
}

func (s *DatagramSession) migrateIfNeeded(from net.Addr) {
	if from == nil {
		return
	}
	s.mu.RLock()
	remote := s.remote
	closed := s.state == SessionClosed
	s.mu.RUnlock()
	if closed || sameAddr(remote, from) {
		return
	}
	_ = s.Migrate(s.ctx, from)
}

func sameAddr(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Network() == right.Network() && left.String() == right.String()
}

type packetDedupWindow struct {
	max   int
	seen  map[uint64]struct{}
	order []uint64
}

func newPacketDedupWindow(max int) *packetDedupWindow {
	if max <= 0 {
		max = defaultDedupWindow
	}
	return &packetDedupWindow{
		max:  max,
		seen: make(map[uint64]struct{}, max),
	}
}

func (w *packetDedupWindow) SeenFirst(packetNumber uint64) bool {
	if w == nil {
		return true
	}
	if _, ok := w.seen[packetNumber]; ok {
		return false
	}
	w.seen[packetNumber] = struct{}{}
	w.order = append(w.order, packetNumber)
	if len(w.order) > w.max {
		evicted := w.order[0]
		copy(w.order, w.order[1:])
		w.order = w.order[:len(w.order)-1]
		delete(w.seen, evicted)
	}
	return true
}

func (s *DatagramSession) stream(streamID StreamID) <-chan []byte {
	return s.streamWithSize(streamID, defaultStreamQueue)
}

func (s *DatagramSession) streamWithSize(streamID StreamID, queueSize int) chan []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.streams[streamID]
	if ok {
		return ch
	}
	ch = make(chan []byte, queueSize)
	s.streams[streamID] = ch
	return ch
}

func NewLoopbackSessionPair(ctx context.Context, pacerPPS float64) (*DatagramSession, *DatagramSession, error) {
	clientTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	serverTransport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		_ = clientTransport.Close()
		return nil, nil, err
	}

	clientKeys, serverKeys, sessionID, err := deriveLoopbackKeys()
	if err != nil {
		_ = clientTransport.Close()
		_ = serverTransport.Close()
		return nil, nil, err
	}

	clientSession, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  clientTransport,
		RemoteAddr: serverTransport.LocalAddr(),
		SendKey:    clientKeys.SendKey,
		RecvKey:    clientKeys.RecvKey,
		Pacer:      NewTokenBucketPacer(pacerPPS),
	})
	if err != nil {
		_ = clientTransport.Close()
		_ = serverTransport.Close()
		return nil, nil, err
	}
	serverSession, err := NewDatagramSession(SessionOptions{
		ID:         sessionID,
		Transport:  serverTransport,
		RemoteAddr: clientTransport.LocalAddr(),
		SendKey:    serverKeys.SendKey,
		RecvKey:    serverKeys.RecvKey,
		Pacer:      NewTokenBucketPacer(pacerPPS),
	})
	if err != nil {
		_ = clientSession.Close()
		_ = serverTransport.Close()
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = clientSession.Close()
		_ = serverSession.Close()
		return nil, nil, err
	}
	return clientSession, serverSession, nil
}

func deriveLoopbackKeys() (TrafficKeys, TrafficKeys, SessionID, error) {
	clientKey, err := NewKeyPair()
	if err != nil {
		return TrafficKeys{}, TrafficKeys{}, SessionID{}, err
	}
	serverKey, err := NewKeyPair()
	if err != nil {
		return TrafficKeys{}, TrafficKeys{}, SessionID{}, err
	}
	sessionID, err := NewSessionID()
	if err != nil {
		return TrafficKeys{}, TrafficKeys{}, SessionID{}, err
	}
	clientKeys, err := clientKey.DeriveTrafficKeys(serverKey.PublicKey(), sessionID, RoleClient)
	if err != nil {
		return TrafficKeys{}, TrafficKeys{}, SessionID{}, err
	}
	serverKeys, err := serverKey.DeriveTrafficKeys(clientKey.PublicKey(), sessionID, RoleServer)
	if err != nil {
		return TrafficKeys{}, TrafficKeys{}, SessionID{}, err
	}
	return clientKeys, serverKeys, sessionID, nil
}

var _ Session = (*DatagramSession)(nil)
