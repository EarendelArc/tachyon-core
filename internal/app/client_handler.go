package app

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/pipeline"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

const capturedPacketStream tgp.StreamID = 0

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
			return errors.New("tgp handler is not configured")
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
		logger.Debug("packet route decision bypassed by core",
			"action", decision.Action,
			"reason", decision.Reason,
			"process", decision.Process.Name,
			"remote", decision.Flow.RemoteIP,
			"remote_port", decision.Flow.RemotePort,
			"bytes", len(packet),
		)
	}
	return nil
}
