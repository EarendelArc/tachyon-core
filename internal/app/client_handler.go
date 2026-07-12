package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/pipeline"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

const capturedPacketStream tgp.StreamID = 0

var (
	ErrDirectTrafficCaptured   = errors.New("direct traffic captured but Core has no direct forwarding path")
	ErrTGPForwarderUnavailable = errors.New("TGP forwarding action selected but no TGP sender is configured")
	ErrUnsupportedClientAction = errors.New("unsupported client packet action")
)

type tgpPacketSender interface {
	SendPacket(ctx context.Context, streamID tgp.StreamID, payload []byte) error
}

type clientPacketHandler struct {
	logger *slog.Logger
	tgp    tgpPacketSender
}

func (h clientPacketHandler) HandlePacket(ctx context.Context, decision pipeline.Decision, packet []byte) error {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}

	switch decision.Action {
	case pipeline.ActionTGP:
		if h.tgp == nil {
			return &pipeline.FatalHandlerError{Err: ErrTGPForwarderUnavailable}
		}
		if decision.Flow.Transport != pidtrack.TransportUDP {
			return errors.New("tgp handler received non-UDP packet")
		}
		flow, udpPayload, err := pipeline.ExtractUDPPayload(packet)
		if err != nil {
			return err
		}
		localIP, err := netip.ParseAddr(flow.LocalIP)
		if err != nil {
			return err
		}
		remoteIP, err := netip.ParseAddr(flow.RemoteIP)
		if err != nil {
			return err
		}
		tunnelPayload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
			LocalIP:    localIP,
			LocalPort:  flow.LocalPort,
			RemoteIP:   remoteIP,
			RemotePort: flow.RemotePort,
			Payload:    udpPayload,
		})
		if err != nil {
			return err
		}
		if err := h.tgp.SendPacket(ctx, capturedPacketStream, tunnelPayload); err != nil {
			return err
		}
		logger.Debug("packet sent via TGP",
			"process", decision.Process.Name,
			"remote", decision.Flow.RemoteIP,
			"remote_port", decision.Flow.RemotePort,
			"bytes", len(udpPayload),
		)
	case pipeline.ActionDrop:
		logger.Debug("packet dropped by route decision",
			"process", decision.Process.Name,
			"remote", decision.Flow.RemoteIP,
			"remote_port", decision.Flow.RemotePort,
		)
	case pipeline.ActionDirect:
		return &pipeline.FatalHandlerError{Err: fmt.Errorf("%w: %s:%d", ErrDirectTrafficCaptured, decision.Flow.RemoteIP, decision.Flow.RemotePort)}
	default:
		return &pipeline.FatalHandlerError{Err: fmt.Errorf("%w: %q", ErrUnsupportedClientAction, decision.Action)}
	}
	return nil
}
