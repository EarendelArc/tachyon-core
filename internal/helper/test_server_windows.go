//go:build windows

package helper

import (
	"context"

	"github.com/tachyon-space/tachyon-core/internal/capturedudp"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

// RunTestServer is a test-only Core Named Pipe v2 endpoint. It has no TUN,
// WFP, proxy, route, or game data path and must never be used in production.
func RunTestServer(ctx context.Context, config Config) error {
	registry, err := capturedudp.NewRegistry(capturedudp.Limits{})
	if err != nil {
		return err
	}
	defer registry.Close()
	server, err := capturedudp.NewNamedPipeServer(registry, capturedudp.NamedPipeConfig{
		Name: config.PipeName, AllowedSIDs: config.AllowedSIDs,
		MinimumIntegrityRID: config.MinimumServerIntegrityRID,
		OperationTimeout:    config.OperationTimeout,
	}, testServerSender{})
	if err != nil {
		return err
	}
	defer server.Close()
	return server.Run(ctx)
}

type testServerSender struct{}

func (testServerSender) SendDatagram(context.Context, tgp.TunnelDatagram) error { return nil }
