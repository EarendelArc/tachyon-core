//go:build !windows

package helper

import "errors"

var ErrServiceUnsupported = errors.New("Windows Service mode is unsupported on this platform")

func RunService(string, Config) error { return ErrServiceUnsupported }
