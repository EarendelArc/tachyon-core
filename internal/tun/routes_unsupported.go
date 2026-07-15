//go:build !windows

package tun

func SelectiveRoutesSupported() bool { return false }

func newPlatformRouteOperator(string, uint64) (routeOperator, error) {
	return nil, ErrSelectiveRoutesUnsupported
}
