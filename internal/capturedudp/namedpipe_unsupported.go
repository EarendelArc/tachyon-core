//go:build !windows

package capturedudp

import "context"

func NewNamedPipeServer(*Registry, NamedPipeConfig) (NamedPipeServer, error) {
	return nil, ErrNamedPipeUnsupported
}

func ServeNamedPipe(context.Context, *Registry, NamedPipeConfig) error {
	return ErrNamedPipeUnsupported
}
