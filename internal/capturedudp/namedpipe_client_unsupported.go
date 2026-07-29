//go:build !windows

package capturedudp

import "context"

func NewNamedPipeClient(config NamedPipeClientConfig, onReply func(context.Context, NamedPipeDelivery) error) (NamedPipeClient, error) {
	return nil, ErrNamedPipeUnsupported
}

func openNamedPipeClient(context.Context, NamedPipeClientConfig) (namedPipeClientConnection, error) {
	return nil, ErrNamedPipeUnsupported
}
