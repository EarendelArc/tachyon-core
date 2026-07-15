//go:build windows

package tun

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

type windowsRouteOperator struct {
	interfaceName string
	run           func(context.Context, ...string) error
}

func SelectiveRoutesSupported() bool { return true }

func newPlatformRouteOperator(interfaceName string) (routeOperator, error) {
	name := strings.TrimSpace(interfaceName)
	if name == "" {
		return nil, errorsNewInterfaceName()
	}
	return &windowsRouteOperator{interfaceName: name, run: runNetshContext}, nil
}

func errorsNewInterfaceName() error {
	return fmt.Errorf("selective routes require a TUN interface name")
}

func (o *windowsRouteOperator) Add(ctx context.Context, prefix netip.Prefix) error {
	return o.run(ctx, windowsRouteArgs("add", o.interfaceName, prefix)...)
}

func (o *windowsRouteOperator) Delete(ctx context.Context, prefix netip.Prefix) error {
	return o.run(ctx, windowsRouteArgs("delete", o.interfaceName, prefix)...)
}

func windowsRouteArgs(verb string, interfaceName string, prefix netip.Prefix) []string {
	family := "ipv6"
	nextHop := "::"
	if prefix.Addr().Is4() {
		family = "ipv4"
		nextHop = "0.0.0.0"
	}
	args := []string{
		"interface", family, verb, "route",
		prefix.Masked().String(),
		"interface=" + interfaceName,
		"nexthop=" + nextHop,
	}
	if verb == "add" {
		args = append(args, "metric=1", "store=active")
	} else {
		args = append(args, "store=active")
	}
	return args
}

func runNetshContext(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v: %w: %s", args, err, strings.TrimSpace(string(output)))
	}
	return nil
}
