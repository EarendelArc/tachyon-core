package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var ErrMultipathTransportClosed = errors.New("multipath transport closed")

const pathAuthenticationRefreshInterval = 10 * time.Second

type MultipathTransport struct {
	paths  []Transport
	ctx    context.Context
	cancel context.CancelFunc
	reads  chan multipathRead
	once   sync.Once

	pathAuthMu   sync.RWMutex
	pathAuth     *clientPathAuthentication
	pathAuthOnce sync.Once
}

type clientPathAuthentication struct {
	sessionID        SessionID
	key              [trafficKeySize]byte
	remote           net.Addr
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
		paths:  filtered,
		ctx:    ctx,
		cancel: cancel,
		reads:  make(chan multipathRead, len(filtered)),
	}
	for index, path := range filtered {
		go t.readLoop(index, path)
	}
	return t, nil
}

func (t *MultipathTransport) EnablePathAuthentication(sessionID SessionID, key [trafficKeySize]byte, remote net.Addr) error {
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

	results := make(chan error, len(t.paths))
	for _, path := range t.paths {
		path := path
		packet := append([]byte(nil), pkt...)
		go func() {
			results <- path.WritePacket(ctx, packet, addr)
		}()
	}

	var failures []error
	successes := 0
	for range t.paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-results:
			if err == nil {
				successes++
				continue
			}
			failures = append(failures, err)
		}
	}
	if successes > 0 {
		return nil
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
	case <-t.ctx.Done():
		return nil, nil, ErrMultipathTransportClosed
	case read := <-t.reads:
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
	t.once.Do(t.cancel)
	var failures []error
	for _, path := range t.paths {
		if err := path.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (t *MultipathTransport) readLoop(index int, path Transport) {
	for {
		packet, from, err := path.ReadPacket(t.ctx)
		if err != nil {
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
	sessionID := auth.sessionID
	key := auth.key
	wantNonce := auth.nonces[index]
	t.pathAuthMu.RUnlock()
	if msg.sessionID != sessionID || msg.clientNonce != wantNonce || !verifyPathControl(msg, key) {
		return true
	}
	sourceKey, ok := newSourceAddrKey(from)
	if !ok {
		return true
	}
	t.pathAuthMu.Lock()
	if t.pathAuth != nil && t.pathAuth.sessionID == sessionID {
		t.pathAuth.authorizedSource[sourceKey] = struct{}{}
	}
	t.pathAuthMu.Unlock()

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
	t.pathAuthMu.RUnlock()

	type request struct {
		index int
		wire  []byte
	}
	requests := make([]request, 0, len(t.paths))
	for index := range t.paths {
		nonce, err := newPathNonce()
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
