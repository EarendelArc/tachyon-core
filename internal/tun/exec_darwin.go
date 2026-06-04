//go:build darwin

package tun

import "os/exec"

func execCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
