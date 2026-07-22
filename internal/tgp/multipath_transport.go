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

var ErrMultipathTransportClosed = errors.New("multipath transport closed")

const pathAuthenticationRefreshInterval = 10 * time.Second

type MultipathTransport struct {
	paths         []Transport
	pathCloseOnce []sync.Once
	ctx           context.Context
	cancel        context.CancelFunc
	reads         chan multipathRead
	readDone      chan struct{}
	readWG        sync.WaitGroup
	closeOnce     sync.Once

	stateMu      sync.Mutex
	pathAlive    []bool
	pathErrors   []error
	pathCloseErr []error
	terminalErr  error
	closeErr     error
	closing      bool

	pathAuthMu   sync.RWMutex
	pathAuth     *clientPathAuthentication
	pathAuthOnce sync.Once
}

type clientPathAuthentication struct {
	sessionID        SessionID
	key              [trafficKeySize]byte
	remote           net.Addr
	clockOffset      time.Duration
	nonces           [][pathControlNonceSize]byte
	authorizedSource map[sourceAddrKey]struct{}
}

type multipathRead struct {
	packet []byte
	from   net.Addr
}

func NewMultipathTransport(paths ...Transport) (*MultipathTransport, error) {
	filtered := make([]Transport, 0, len(paths))
	for _, path := range paths {
		if path != nil {
			filtered = append(filtered, path)
		}
	}
	if len(filtered) == 0 {
		return nil, errors.New("multipath transport requires at least one path")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &MultipathTransport{
		paths:         filtered,
		pathCloseOnce: make([]sync.Once, len(filtered)),
		ctx:           ctx,
		cancel:        cancel,
		reads:         make(chan multipathRead, len(filtered)),
		readDone:      make(chan struct{}),
		pathAlive:     make([]bool, len(filtered)),
		pathErrors:    make([]error, len(filtered)),
		pathCloseErr:  make([]error, len(filtered)),
	}
	for index := range t.pathAlive {
		t.pathAlive[index] = true
	}
	t.readWG.Add(len(filtered))
	for index, path := range filtered {
		go t.readLoop(index, path)
	}
	go t.finishReads()
	return t, nil
}

func (t *MultipathTransport) EnablePathAuthentication(sessionID SessionID, key [trafficKeySize]byte, remote net.Addr, clockOffset time.Duration) error {
	if t == nil || remote == nil {
		return errors.New("path authentication requires a transport and remote address")
	}
	remoteKey, ok := newSourceAddrKey(remote)
	if !ok {
		return errors.New("path authentication requires a routable remote address")
	}
	t.pathAuthMu.Lock()
	t.pathAuth = &clientPathAuthentication{
		sessionID:        sessionID,
		key:              key,
		remote:           remote,
		clockOffset:      clockOffset,
		nonces:           make([][pathControlNonceSize]byte, len(t.paths)),
		authorizedSource: map[sourceAddrKey]struct{}{remoteKey: {}},
	}
	t.pathAuthMu.Unlock()

	if err := t.refreshPathAuthentication(); err != nil {
		return err
	}
	t.pathAuthOnce.Do(func() { go t.pathAuthenticationLoop() })
	return nil
}

func (t *MultipathTransport) IsSourceAuthorized(addr net.Addr) bool {
	key, ok := newSourceAddrKey(addr)
	if !ok {
		return false
	}
	t.pathAuthMu.RLock()
	defer t.pathAuthMu.RUnlock()
	if t.pathAuth == nil {
		return false
	}
	_, ok = t.pathAuth.authorizedSource[key]
	return ok
}

func (t *MultipathTransport) WritePacket(ctx context.Context, pkt []byte, addr net.Addr) error {
	if t == nil || len(t.paths) == 0 {
		return errors.New("nil multipath transport")
	}
	if addr == nil {
		return errors.New("nil multipath remote address")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	indexes, terminalErr := t.activePathIndexes()
	if len(indexes) == 0 {
		return terminalErr
	}
	writeCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(t.ctx, cancel)
	var pending atomic.Int32
	pending.Store(int32(len(indexes)))

	results := make(chan error, len(indexes))
	for _, index := range indexes {
		path := t.paths[index]
		packet := append([]byte(nil), pkt...)
		go func() {
			defer func() {
				if pending.Add(-1) == 0 {
					stop()
					cancel()
				}
			}()
			results <- path.WritePacket(writeCtx, packet, addr)
		}()
	}

	var failures []error
	for range indexes {
		select {
		case <-writeCtx.Done():
			if err := ctx.Err(); err != nil {
				return err
			}
			return t.readTerminalError()
		case err := <-results:
			if err == nil {
				return nil
			}
			failures = append(failures, err)
		}
	}
	return fmt.Errorf("write multipath packet: %w", errors.Join(failures...))
}

func (t *MultipathTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	if t == nil {
		return nil, nil, errors.New("nil multipath transport")
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case read, ok := <-t.reads:
		if !ok {
			return nil, nil, t.readTerminalError()
		}
		return read.packet, read.from, nil
	}
}

func (t *MultipathTransport) LocalAddr() net.Addr {
	if t == nil || len(t.paths) == 0 {
		return nil
	}
	return t.paths[0].LocalAddr()
}

func (t *MultipathTransport) Close() error {
	if t == nil {
		return nil
	}
	t.closeOnce.Do(func() {
		t.stateMu.Lock()
		t.closing = true
		if t.terminalErr == nil {
			t.terminalErr = ErrMultipathTransportClosed
		}
		t.stateMu.Unlock()
		t.cancel()
		for index := range t.paths {
			t.closePath(index)
		}
		<-t.readDone

		t.stateMu.Lock()
		t.closeErr = errors.Join(t.pathCloseErr...)
		t.stateMu.Unlock()
	})
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	return t.closeErr
}

func (t *MultipathTransport) readLoop(index int, path Transport) {
	defer t.readWG.Done()
	defer t.closePath(index)
	for {
		packet, from, err := path.ReadPacket(t.ctx)
		if err != nil {
			t.pathTerminated(index, err)
			return
		}
		if t.handlePathControl(index, path, packet, from) {
			continue
		}
		copied := append([]byte(nil), packet...)
		select {
		case <-t.ctx.Done():
			return
		case t.reads <- multipathRead{packet: copied, from: from}:
		}
	}
}

func (t *MultipathTransport) pathTerminated(index int, err error) {
	t.stateMu.Lock()
	if index < 0 || index >= len(t.pathAlive) || !t.pathAlive[index] {
		t.stateMu.Unlock()
		return
	}
	t.pathAlive[index] = false
	t.pathErrors[index] = err
	remaining := 0
	for _, alive := range t.pathAlive {
		if alive {
			remaining++
		}
	}
	if remaining == 0 && !t.closing && t.terminalErr == nil {
		t.terminalErr = fmt.Errorf("all multipath read paths failed: %w", errors.Join(t.pathErrors...))
	}
	t.stateMu.Unlock()
	if remaining == 0 {
		t.cancel()
	}
}

func (t *MultipathTransport) closePath(index int) {
	if index < 0 || index >= len(t.paths) {
		return
	}
	t.pathCloseOnce[index].Do(func() {
		err := t.paths[index].Close()
		t.stateMu.Lock()
		t.pathCloseErr[index] = err
		t.stateMu.Unlock()
	})
}

func (t *MultipathTransport) finishReads() {
	t.readWG.Wait()
	t.stateMu.Lock()
	if t.terminalErr == nil {
		t.terminalErr = ErrMultipathTransportClosed
	}
	t.stateMu.Unlock()
	close(t.reads)
	close(t.readDone)
}

func (t *MultipathTransport) activePathIndexes() ([]int, error) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	indexes := make([]int, 0, len(t.pathAlive))
	for index, alive := range t.pathAlive {
		if alive {
			indexes = append(indexes, index)
		}
	}
	if len(indexes) == 0 {
		return nil, t.terminalErr
	}
	return indexes, nil
}

func (t *MultipathTransport) readTerminalError() error {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return ErrMultipathTransportClosed
}

func (t *MultipathTransport) handlePathControl(index int, path Transport, packet []byte, from net.Addr) bool {
	msg, err := parsePathControl(packet)
	if err != nil {
		return false
	}
	if msg.msgType != pathControlChallenge {
		return true
	}

	t.pathAuthMu.RLock()
	auth := t.pathAuth
	if auth == nil || index < 0 || index >= len(auth.nonces) {
		t.pathAuthMu.RUnlock()
		return true
	}
	sourceKey, sourceKnown := newSourceAddrKey(from)
	if !sourceKnown {
		t.pathAuthMu.RUnlock()
		return true
	}
	sessionID := auth.sessionID
	key := auth.key
	wantNonce := auth.nonces[index]
	_, sourceAuthorized := auth.authorizedSource[sourceKey]
	t.pathAuthMu.RUnlock()
	if !sourceAuthorized || msg.sessionID != sessionID || msg.clientNonce != wantNonce || !verifyPathControl(msg, key) {
		return true
	}

	response, err := marshalPathControl(pathControlResponse, sessionID, msg.clientNonce, msg.serverNonce, key)
	if err == nil {
		_ = path.WritePacket(t.ctx, response, from)
	}
	return true
}

func (t *MultipathTransport) pathAuthenticationLoop() {
	ticker := time.NewTicker(pathAuthenticationRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			_ = t.refreshPathAuthentication()
		}
	}
}

func (t *MultipathTransport) refreshPathAuthentication() error {
	t.pathAuthMu.RLock()
	auth := t.pathAuth
	if auth == nil {
		t.pathAuthMu.RUnlock()
		return errors.New("path authentication is not configured")
	}
	sessionID := auth.sessionID
	key := auth.key
	remote := auth.remote
	clockOffset := auth.clockOffset
	t.pathAuthMu.RUnlock()

	type request struct {
		index int
		wire  []byte
	}
	requests := make([]request, 0, len(t.paths))
	for index := range t.paths {
		nonce, err := newPathRequestNonce(time.Now().Add(clockOffset))
		if err != nil {
			return err
		}
		wire, err := marshalPathControl(pathControlRequest, sessionID, nonce, [pathControlNonceSize]byte{}, key)
		if err != nil {
			return err
		}
		t.pathAuthMu.Lock()
		if t.pathAuth != nil && index < len(t.pathAuth.nonces) {
			t.pathAuth.nonces[index] = nonce
		}
		t.pathAuthMu.Unlock()
		requests = append(requests, request{index: index, wire: wire})
	}

	successes := 0
	var failures []error
	for _, item := range requests {
		if err := t.paths[item.index].WritePacket(t.ctx, item.wire, remote); err != nil {
			failures = append(failures, err)
			continue
		}
		successes++
	}
	if successes > 0 {
		return nil
	}
	return fmt.Errorf("send path authentication requests: %w", errors.Join(failures...))
}

var _ Transport = (*MultipathTransport)(nil)
var _ sourceAuthorizer = (*MultipathTransport)(nil)
