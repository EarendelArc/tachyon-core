//go:build !windows

package tun

func SelectiveRoutesSupported() bool { return false }

func newPlatformRouteOperator(string) (routeOperator, error) {
	return nil, ErrSelectiveRoutesUnsupported
}
