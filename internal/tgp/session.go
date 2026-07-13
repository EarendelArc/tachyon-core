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
	defaultStreamQueue = 64
	defaultDedupWindow = 4096
)

var (
	ErrSessionClosed     = errors.New("tgp session closed")
	ErrSessionIDMismatch = errors.New("tgp session id mismatch")
	ErrMigrationDisabled = errors.New("tgp connection migration disabled")
)

type SessionOptions struct {
	ID          SessionID
	Transport   Transport
	RemoteAddr  net.Addr
	SendKey     [trafficKeySize]byte
	RecvKey     [trafficKeySize]byte
	Pacer       Pacer
	StreamQueue int
	FECBuffer   *FECReceiveBuffer
	FEC         FECOptions
	// DisableMigration rejects authenticated packets that arrive from a source
	// address different from the established remote address.
	DisableMigration bool
}

type sourceAuthorizer interface {
	IsSourceAuthorized(net.Addr) bool
}

type managedReturnPath interface {
	ManagesReturnPath() bool
}

type sourceActivityObserver interface {
	ObserveAuthorizedSource(net.Addr)
}

type FECOptions struct {
	DataShards       int
	ParityShards     int
	MaxReceiveGroups int
	GroupTimeout     time.Duration
	Dynamic          bool
	AdaptWindow      int
}

func (o FECOptions) enabled() bool {
	return o.DataShards > 0 && o.ParityShards > 0
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

	mu               sync.RWMutex
	state            SessionState
	remote           net.Addr
	streams          map[StreamID]chan []byte
	dedup            *packetDedupWindow
	fecRx            *FECReceiveBuffer
	fec              FECOptions
	fecAdapt         *FECAdaptiveController
	disableMigration bool
	fecMu            sync.Mutex
	fecTx            map[StreamID]*fecSendGroup
	fecGroup         uint32

	packetNo atomic.Uint64
	stats    sessionCounters
}

type fecSendGroup struct {
	id        uint32
	createdAt time.Time
	payloads  [][]byte
}

type fecRepairBatch struct {
	streamID   StreamID
	groupID    uint32
	total      int
	dataShards int
	shards     []fecRepairShard
}

type fecRepairShard struct {
	index   int
	payload []byte
}

type sessionCounters struct {
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	fecRecovered  atomic.Uint64
	packetLossPPM atomic.Uint64
	migrations    atomic.Uint32
}

func NewDatagramSession(opts SessionOptions) (*DatagramSession, error) {
	if opts.Transport == nil {
		return nil, errors.New("tgp session transport is required")
	}
	if opts.RemoteAddr == nil {
		return nil, errors.New("tgp session remote address is required")
	}
	if err := validateFECOptions(opts.FEC); err != nil {
		return nil, err
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
	fecRx := opts.FECBuffer
	if fecRx == nil {
		fecRx = NewFECReceiveBuffer(nil, opts.FEC.MaxReceiveGroups)
	}
	var fecAdapt *FECAdaptiveController
	if opts.FEC.enabled() && opts.FEC.Dynamic {
		fecAdapt = NewFECAdaptiveController(opts.FEC.DataShards, opts.FEC.DataShards, opts.FEC.AdaptWindow)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &DatagramSession{
		id:               opts.ID,
		transport:        opts.Transport,
		sendCodec:        sendCodec,
		recvCodec:        recvCodec,
		pacer:            pacer,
		ctx:              ctx,
		cancel:           cancel,
		done:             make(chan struct{}),
		state:            SessionEstablished,
		remote:           opts.RemoteAddr,
		streams:          make(map[StreamID]chan []byte),
		dedup:            newPacketDedupWindow(defaultDedupWindow),
		fecRx:            fecRx,
		fec:              opts.FEC,
		fecAdapt:         fecAdapt,
		disableMigration: opts.DisableMigration,
		fecTx:            make(map[StreamID]*fecSendGroup),
	}
	s.streams[0] = make(chan []byte, queueSize)

	go s.readLoop(queueSize)
	if s.fec.enabled() && s.fec.GroupTimeout > 0 {
		go s.fecFlushLoop()
	}
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
	if s.fecEnabled() {
		return s.sendPacketWithFEC(ctx, streamID, payload)
	}
	return s.sendWirePayload(ctx, streamID, payload, nil, uint64(len(payload)))
}

func (s *DatagramSession) fecEnabled() bool {
	s.fecMu.Lock()
	defer s.fecMu.Unlock()
	return s.fec.enabled()
}

func (s *DatagramSession) sendPacketWithFEC(ctx context.Context, streamID StreamID, payload []byte) error {
	dataPayload, parityPayloads, groupID, index, total, dataShards, err := s.nextFECShards(streamID, payload)
	if err != nil {
		return err
	}
	configureData := func(header *InnerHeader) {
		header.FECGroup = groupID
		header.FECIndex = uint8(index)
		header.FECTotal = uint8(total)
		header.FECDataShards = uint8(dataShards)
	}
	if err := s.sendWirePayload(ctx, streamID, dataPayload, configureData, uint64(len(payload))); err != nil {
		return err
	}
	for parityOffset, parityPayload := range parityPayloads {
		parityIndex := dataShards + parityOffset
		configureParity := func(header *InnerHeader) {
			header.Flags |= FlagFEC
			header.FECGroup = groupID
			header.FECIndex = uint8(parityIndex)
			header.FECTotal = uint8(total)
			header.FECDataShards = uint8(dataShards)
		}
		if err := s.sendWirePayload(ctx, streamID, parityPayload, configureParity, 0); err != nil {
			return err
		}
	}
	return nil
}

func (s *DatagramSession) nextFECShards(streamID StreamID, payload []byte) ([]byte, [][]byte, uint32, int, int, int, error) {
	s.fecMu.Lock()
	defer s.fecMu.Unlock()

	dataShards := s.fec.DataShards
	parityShards := s.fec.ParityShards
	if err := validateFECParams(dataShards, parityShards); err != nil {
		return nil, nil, 0, 0, 0, 0, err
	}
	if dataShards+parityShards > 0xff {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("%w: total fec shards exceed 255", ErrInvalidFECParams)
	}
	group := s.fecTx[streamID]
	if group == nil {
		s.fecGroup++
		group = &fecSendGroup{id: s.fecGroup, createdAt: time.Now()}
		s.fecTx[streamID] = group
	}
	if len(group.payloads) >= dataShards {
		s.fecGroup++
		group = &fecSendGroup{id: s.fecGroup, createdAt: time.Now()}
		s.fecTx[streamID] = group
	}

	index := len(group.payloads)
	group.payloads = append(group.payloads, append([]byte(nil), payload...))
	dataPayload, err := frameFECData(payload, len(payload)+fecLengthPrefixSize)
	if err != nil {
		return nil, nil, 0, 0, 0, 0, err
	}

	var parityPayloads [][]byte
	if len(group.payloads) == dataShards {
		codec := NewReedSolomonCodec()
		shards, err := codec.Encode(group.payloads, dataShards, parityShards)
		if err != nil {
			return nil, nil, 0, 0, 0, 0, err
		}
		parityPayloads = cloneShardRange(shards[dataShards:])
		delete(s.fecTx, streamID)
	}
	return dataPayload, parityPayloads, group.id, index, dataShards + parityShards, dataShards, nil
}

func (s *DatagramSession) fecFlushLoop() {
	interval := s.fec.GroupTimeout / 2
	if interval <= 0 {
		interval = s.fec.GroupTimeout
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			batches := s.expiredFECRepairBatches(now)
			for _, batch := range batches {
				_ = s.sendFECRepairBatch(s.ctx, batch)
			}
		}
	}
}

func (s *DatagramSession) expiredFECRepairBatches(now time.Time) []fecRepairBatch {
	s.fecMu.Lock()
	defer s.fecMu.Unlock()

	if !s.fec.enabled() || s.fec.GroupTimeout <= 0 {
		return nil
	}
	dataShards := s.fec.DataShards
	parityShards := s.fec.ParityShards
	if err := validateFECParams(dataShards, parityShards); err != nil {
		return nil
	}

	var batches []fecRepairBatch
	for streamID, group := range s.fecTx {
		if len(group.payloads) == 0 || len(group.payloads) >= dataShards {
			continue
		}
		if now.Sub(group.createdAt) < s.fec.GroupTimeout {
			continue
		}
		shards, err := NewReedSolomonCodec().Encode(group.payloads, dataShards, parityShards)
		if err != nil {
			continue
		}
		repair := make([]fecRepairShard, 0, dataShards-len(group.payloads)+parityShards)
		for index := len(group.payloads); index < dataShards; index++ {
			repair = append(repair, fecRepairShard{
				index:   index,
				payload: append([]byte(nil), shards[index]...),
			})
		}
		for index := dataShards; index < len(shards); index++ {
			repair = append(repair, fecRepairShard{
				index:   index,
				payload: append([]byte(nil), shards[index]...),
			})
		}
		batches = append(batches, fecRepairBatch{
			streamID:   streamID,
			groupID:    group.id,
			total:      dataShards + parityShards,
			dataShards: dataShards,
			shards:     repair,
		})
		delete(s.fecTx, streamID)
	}
	return batches
}

func (s *DatagramSession) sendFECRepairBatch(ctx context.Context, batch fecRepairBatch) error {
	for _, shard := range batch.shards {
		index := shard.index
		configure := func(header *InnerHeader) {
			header.Flags |= FlagFEC
			header.FECGroup = batch.groupID
			header.FECIndex = uint8(index)
			header.FECTotal = uint8(batch.total)
			header.FECDataShards = uint8(batch.dataShards)
		}
		if err := s.sendWirePayload(ctx, batch.streamID, shard.payload, configure, 0); err != nil {
			return err
		}
	}
	return nil
}

func (s *DatagramSession) sendWirePayload(ctx context.Context, streamID StreamID, payload []byte, configure func(*InnerHeader), accountedBytes uint64) error {
	if err := s.pacer.Consume(ctx); err != nil {
		return err
	}
	packetNo := s.packetNo.Add(1)
	header, err := NewDataHeader(s.id, streamID, packetNo, len(payload))
	if err != nil {
		return err
	}
	if configure != nil {
		configure(&header)
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
	if accountedBytes > 0 {
		s.stats.bytesSent.Add(accountedBytes)
	}
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
	if s.disableMigration {
		return ErrMigrationDisabled
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
		PacketLoss:    float64(s.stats.packetLossPPM.Load()) / 1_000_000,
		BytesSent:     s.stats.bytesSent.Load(),
		BytesReceived: s.stats.bytesReceived.Load(),
		FECRecovered:  s.stats.fecRecovered.Load(),
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
		if !s.sourceEligibleForReplay(from) {
			continue
		}
		if !s.dedup.SeenFirst(packet.Inner.PacketNumber) {
			continue
		}
		if !s.acceptSource(from) {
			continue
		}
		result, err := s.fecRx.AddPacket(packet)
		if err != nil {
			continue
		}
		if observer, ok := s.transport.(sourceActivityObserver); ok {
			observer.ObserveAuthorizedSource(from)
		}
		if !result.Ready {
			continue
		}
		if result.RecoveredShards > 0 {
			s.stats.fecRecovered.Add(uint64(result.RecoveredShards))
		}
		s.observeFECDelivery(len(result.Payloads), result.RecoveredShards)
		for _, payload := range result.Payloads {
			s.stats.bytesReceived.Add(uint64(len(payload)))
			ch := s.streamWithSize(packet.Inner.StreamID, queueSize)
			select {
			case ch <- payload:
			default:
				// Prefer dropping a stale game datagram over adding queue latency.
			}
		}
	}
}

func (s *DatagramSession) sourceEligibleForReplay(from net.Addr) bool {
	if from == nil {
		return true
	}
	s.mu.RLock()
	remote := s.remote
	disableMigration := s.disableMigration
	closed := s.state == SessionClosed
	s.mu.RUnlock()
	if closed {
		return false
	}
	if sameAddr(remote, from) {
		return true
	}
	if disableMigration {
		return false
	}
	if authorizer, ok := s.transport.(sourceAuthorizer); ok {
		return authorizer.IsSourceAuthorized(from)
	}
	return true
}

func (s *DatagramSession) observeFECDelivery(delivered, recovered int) {
	s.fecMu.Lock()
	defer s.fecMu.Unlock()
	if s.fecAdapt == nil {
		return
	}
	parity, lossRate, updated := s.fecAdapt.Observe(delivered, recovered)
	s.stats.packetLossPPM.Store(uint64(lossRate * 1_000_000))
	if updated && parity != s.fec.ParityShards {
		s.fec.ParityShards = parity
	}
}

func (s *DatagramSession) acceptSource(from net.Addr) bool {
	if from == nil {
		return true
	}
	s.mu.RLock()
	remote := s.remote
	closed := s.state == SessionClosed
	disableMigration := s.disableMigration
	s.mu.RUnlock()
	if closed {
		return false
	}
	if sameAddr(remote, from) {
		return true
	}
	if disableMigration {
		return false
	}
	if manager, ok := s.transport.(managedReturnPath); ok && manager.ManagesReturnPath() {
		return true
	}
	return s.Migrate(s.ctx, from) == nil
}

func sameAddr(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Network() == right.Network() && left.String() == right.String()
}

func cloneShardRange(shards [][]byte) [][]byte {
	out := make([][]byte, len(shards))
	for i, shard := range shards {
		out[i] = append([]byte(nil), shard...)
	}
	return out
}

type packetDedupWindow struct {
	max         uint64
	highest     uint64
	initialized bool
	seen        map[uint64]struct{}
}

func newPacketDedupWindow(max int) *packetDedupWindow {
	if max <= 0 {
		max = defaultDedupWindow
	}
	return &packetDedupWindow{
		max:  uint64(max),
		seen: make(map[uint64]struct{}, max),
	}
}

func (w *packetDedupWindow) SeenFirst(packetNumber uint64) bool {
	if w == nil {
		return true
	}
	if !w.initialized {
		w.initialized = true
		w.highest = packetNumber
		w.seen[packetNumber] = struct{}{}
		return true
	}
	if packetNumber > w.highest {
		w.highest = packetNumber
		var oldest uint64
		if w.highest >= w.max {
			oldest = w.highest - w.max + 1
		}
		for seen := range w.seen {
			if seen < oldest {
				delete(w.seen, seen)
			}
		}
	} else if w.highest-packetNumber >= w.max {
		return false
	}
	if _, ok := w.seen[packetNumber]; ok {
		return false
	}
	w.seen[packetNumber] = struct{}{}
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
