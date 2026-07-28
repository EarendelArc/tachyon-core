//go:build !windows

package capturedudp

import "context"

func ServeNamedPipe(context.Context, *Registry, NamedPipeConfig) error {
	return ErrNamedPipeUnsupported
}
