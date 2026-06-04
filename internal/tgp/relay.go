package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

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
	ListenAddr string
	Transport  Transport
	PacerPPS   float64
	Handler    RelayHandler
}

type Relay struct {
	listenAddr string
	pacerPPS   float64
	handler    RelayHandler

	mu        sync.Mutex
	transport Transport
	session   Session
}

func NewRelay(opts RelayOptions) (*Relay, error) {
	if opts.Transport == nil && opts.ListenAddr == "" {
		return nil, errors.New("relay listen address or transport is required")
	}
	handler := opts.Handler
	if handler == nil {
		handler = RelayHandlerFunc(func(context.Context, RelayPacket) error { return nil })
	}
	return &Relay{
		listenAddr: opts.ListenAddr,
		pacerPPS:   opts.PacerPPS,
		handler:    handler,
		transport:  opts.Transport,
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

	session, err := AcceptSession(ctx, transport, r.pacerPPS)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("accept tgp session: %w", err)
	}
	r.setSession(session)

	for {
		payload, err := session.RecvPacket(ctx, capturedPacketStreamID)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ErrSessionClosed) {
				return nil
			}
			return fmt.Errorf("receive tgp relay packet: %w", err)
		}
		packet := RelayPacket{
			SessionID: session.ID(),
			Session:   session,
			Payload:   append([]byte(nil), payload...),
		}
		if err := r.handler.HandleRelayPacket(ctx, packet); err != nil {
			return fmt.Errorf("handle relay packet: %w", err)
		}
	}
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
	session := r.session
	transport := r.transport
	r.session = nil
	r.transport = nil
	r.mu.Unlock()

	if session != nil {
		return session.Close()
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

func (r *Relay) setSession(session Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session = session
}

const capturedPacketStreamID StreamID = 0
