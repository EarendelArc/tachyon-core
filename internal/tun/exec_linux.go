//go:build linux

package tun

import (
	"os/exec"
)

// execCommand is the platform exec helper used by the Linux TUN implementation.
func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
