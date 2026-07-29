//go:build !windows

package helper

import (
	"context"
	"errors"
)

func RunTestServer(context.Context, Config) error {
	return errors.New("test-only Windows Named Pipe server is unsupported on this platform")
}
