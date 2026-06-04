package app

import (
	"context"
	"log/slog"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

type serverRelayHandler struct {
	logger *slog.Logger
}

func (h serverRelayHandler) HandleRelayPacket(ctx context.Context, packet tgp.RelayPacket) error {
	_ = ctx
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Debug("TGP relay received captured packet",
		"session", packet.SessionID,
		"bytes", len(packet.Payload),
	)
	return nil
}
