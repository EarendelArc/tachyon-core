package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

type gameUDPForwarder interface {
	ForwardUDP(ctx context.Context, target netip.AddrPort, payload []byte) error
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
		if err := h.forwarder.ForwardUDP(ctx, target, datagram.Payload); err != nil {
			return err
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

func (f netUDPForwarder) ForwardUDP(ctx context.Context, target netip.AddrPort, payload []byte) error {
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
		return fmt.Errorf("dial game udp %s: %w", target, err)
	}
	defer conn.Close()
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write game udp %s: %w", target, err)
	}
	return nil
}
