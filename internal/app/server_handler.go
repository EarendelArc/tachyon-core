package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

type gameUDPForwarder interface {
	ForwardUDP(ctx context.Context, target netip.AddrPort, payload []byte) ([]byte, error)
}

type serverRelayHandler struct {
	logger    *slog.Logger
	forwarder gameUDPForwarder
}

func (h serverRelayHandler) HandleRelayPacket(ctx context.Context, packet tgp.RelayPacket) error {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}

	datagram, err := tgp.ParseTunnelDatagram(packet.Payload)
	if err != nil {
		return err
	}
	target := datagram.RemoteAddrPort()
	if h.forwarder != nil {
		response, err := h.forwarder.ForwardUDP(ctx, target, datagram.Payload)
		if err != nil {
			return err
		}
		if len(response) > 0 && packet.Session != nil {
			responsePayload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
				LocalIP:    datagram.LocalIP,
				LocalPort:  datagram.LocalPort,
				RemoteIP:   datagram.RemoteIP,
				RemotePort: datagram.RemotePort,
				Payload:    response,
			})
			if err != nil {
				return err
			}
			if err := packet.Session.SendPacket(ctx, capturedPacketStream, responsePayload); err != nil {
				return err
			}
		}
	}
	logger.Debug("TGP relay forwarded UDP payload",
		"session", packet.SessionID,
		"target", target,
		"bytes", len(datagram.Payload),
	)
	return nil
}

type netUDPForwarder struct {
	timeout time.Duration
}

func (f netUDPForwarder) ForwardUDP(ctx context.Context, target netip.AddrPort, payload []byte) ([]byte, error) {
	timeout := f.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", target.String())
	if err != nil {
		return nil, fmt.Errorf("dial game udp %s: %w", target, err)
	}
	defer conn.Close()
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write game udp %s: %w", target, err)
	}
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		return nil, fmt.Errorf("read game udp %s: %w", target, err)
	}
	return append([]byte(nil), buf[:n]...), nil
}
