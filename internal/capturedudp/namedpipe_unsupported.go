//go:build !windows

package capturedudp

import "context"

func NewNamedPipeServer(*Registry, NamedPipeConfig, NamedPipeDatagramSender) (NamedPipeServer, error) {
	return nil, ErrNamedPipeUnsupported
}

func ServeNamedPipe(context.Context, *Registry, NamedPipeConfig, NamedPipeDatagramSender) error {
	return ErrNamedPipeUnsupported
}
