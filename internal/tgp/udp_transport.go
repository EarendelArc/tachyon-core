package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type UDPTransport struct {
	conn    net.PacketConn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func ListenUDP(addr string) (*UDPTransport, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %q: %w", addr, err)
	}
	return &UDPTransport{conn: conn}, nil
}

func NewUDPTransport(conn net.PacketConn) *UDPTransport {
	return &UDPTransport{conn: conn}
}

func (t *UDPTransport) WritePacket(ctx context.Context, pkt []byte, addr net.Addr) error {
	if t == nil || t.conn == nil {
		return errors.New("nil udp transport")
	}
	if addr == nil {
		return errors.New("nil udp remote address")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, hasDeadline := ctx.Deadline()
	if err := t.conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set udp write deadline: %w", err)
	}
	stop, interrupted := interruptPacketConnOnCancel(ctx, func(deadline time.Time) error {
		return t.conn.SetWriteDeadline(deadline)
	})
	_, writeErr := t.conn.WriteTo(pkt, addr)
	stop()
	<-interrupted
	clearErr := t.conn.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		return normalizePacketConnError(ctx, deadline, hasDeadline, "write udp packet", writeErr)
	}
	if clearErr != nil {
		return fmt.Errorf("clear udp write deadline: %w", clearErr)
	}
	return nil
}

func normalizePacketConnError(ctx context.Context, deadline time.Time, hasDeadline bool, operation string, operationErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var timeoutErr interface{ Timeout() bool }
	if hasDeadline && errors.As(operationErr, &timeoutErr) && timeoutErr.Timeout() {
		// The socket deadline and the context timer are armed independently. The
		// socket can report its timeout just before context.Err observes the same
		// deadline. The recorded deadline identifies that boundary without
		// reclassifying an unrelated, earlier socket timeout.
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return fmt.Errorf("%s: %w", operation, operationErr)
}

func interruptPacketConnOnCancel(ctx context.Context, setDeadline func(time.Time) error) (func(), <-chan struct{}) {
	done := make(chan struct{})
	stopAfterFunc := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())
		close(done)
	})
	stop := func() {
		if stopAfterFunc() {
			close(done)
		}
	}
	return stop, done
}

func (t *UDPTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	if t == nil || t.conn == nil {
		return nil, nil, errors.New("nil udp transport")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	deadline, hasDeadline := ctx.Deadline()
	if err := t.conn.SetReadDeadline(deadline); err != nil {
		return nil, nil, fmt.Errorf("set udp read deadline: %w", err)
	}
	stop, interrupted := interruptPacketConnOnCancel(ctx, func(deadline time.Time) error {
		return t.conn.SetReadDeadline(deadline)
	})
	buf := make([]byte, 65535)
	n, from, readErr := t.conn.ReadFrom(buf)
	stop()
	<-interrupted
	clearErr := t.conn.SetReadDeadline(time.Time{})
	if readErr != nil {
		return nil, nil, normalizePacketConnError(ctx, deadline, hasDeadline, "read udp packet", readErr)
	}
	if clearErr != nil {
		return nil, nil, fmt.Errorf("clear udp read deadline: %w", clearErr)
	}
	pkt := make([]byte, n)
	copy(pkt, buf[:n])
	return pkt, from, nil
}

func (t *UDPTransport) LocalAddr() net.Addr {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.LocalAddr()
}

func (t *UDPTransport) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

var _ Transport = (*UDPTransport)(nil)
