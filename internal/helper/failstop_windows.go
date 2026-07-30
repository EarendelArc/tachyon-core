//go:build windows

package helper

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

// defaultFailStop is deliberately process-wide. A production provider contract
// requires a dynamic WFP session so terminating the helper rolls back provider
// state even when Stop is unresponsive.
func defaultFailStop(context.Context) error {
	if err := windows.TerminateProcess(windows.CurrentProcess(), 1); err != nil {
		return fmt.Errorf("terminate helper after provider stop timeout: %w", err)
	}
	return nil
}
