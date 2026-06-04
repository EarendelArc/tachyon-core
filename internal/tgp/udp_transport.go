package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

const defaultReadPollInterval = 100 * time.Millisecond

type UDPTransport struct {
	conn net.PacketConn
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
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.conn.SetWriteDeadline(deadline)
		defer t.conn.SetWriteDeadline(time.Time{})
	}
	if _, err := t.conn.WriteTo(pkt, addr); err != nil {
		return fmt.Errorf("write udp packet: %w", err)
	}
	return nil
}

func (t *UDPTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	if t == nil || t.conn == nil {
		return nil, nil, errors.New("nil udp transport")
	}
	buf := make([]byte, 65535)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		_ = t.conn.SetReadDeadline(time.Now().Add(defaultReadPollInterval))
		n, from, err := t.conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, fmt.Errorf("read udp packet: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		return pkt, from, nil
	}
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
