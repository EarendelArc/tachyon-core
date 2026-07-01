package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

var ErrMultipathTransportClosed = errors.New("multipath transport closed")

type MultipathTransport struct {
	paths  []Transport
	ctx    context.Context
	cancel context.CancelFunc
	reads  chan multipathRead
	once   sync.Once
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
	for _, path := range filtered {
		go t.readLoop(path)
	}
	return t, nil
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

func (t *MultipathTransport) readLoop(path Transport) {
	for {
		packet, from, err := path.ReadPacket(t.ctx)
		if err != nil {
			return
		}
		copied := append([]byte(nil), packet...)
		select {
		case <-t.ctx.Done():
			return
		case t.reads <- multipathRead{packet: copied, from: from}:
		}
	}
}

var _ Transport = (*MultipathTransport)(nil)
