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
	deadline, _ := ctx.Deadline()
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
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("write udp packet: %w", writeErr)
	}
	if clearErr != nil {
		return fmt.Errorf("clear udp write deadline: %w", clearErr)
	}
	return nil
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
	deadline, _ := ctx.Deadline()
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
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("read udp packet: %w", readErr)
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
