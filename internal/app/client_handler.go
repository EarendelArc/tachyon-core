package app

import (
	"context"
	"errors"
	"log/slog"

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
		if err := h.tgp.SendPacket(ctx, capturedPacketStream, packet); err != nil {
			return err
		}
		logger.Debug("packet sent via TGP",
			"process", decision.Process.Name,
			"remote", decision.Flow.RemoteIP,
			"remote_port", decision.Flow.RemotePort,
			"bytes", len(packet),
		)
	case pipeline.ActionDrop:
		logger.Debug("packet dropped by route decision",
			"process", decision.Process.Name,
			"remote", decision.Flow.RemoteIP,
			"remote_port", decision.Flow.RemotePort,
		)
	case pipeline.ActionDirect, pipeline.ActionXray:
		logger.Debug("packet route decision pending transport implementation",
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
