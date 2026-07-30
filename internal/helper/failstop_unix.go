//go:build !windows

package helper

import (
	"context"
	"errors"
)

func defaultFailStop(context.Context) error {
	return errors.New("provider stop timed out; fail-stop is only implemented for the Windows helper")
}
