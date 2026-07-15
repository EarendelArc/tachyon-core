package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

var (
	ErrSelectiveRoutesUnsupported = errors.New("selective TUN routes are not supported on this platform")
	ErrRelayRouteConflict         = errors.New("TGP relay address is covered by a game destination route")
)

const routeCleanupTimeout = 15 * time.Second

// SelectiveRouteOptions describes destination routes owned by one Core run.
// Destinations are OS-level routes: every packet to these prefixes enters the
// TUN, regardless of which process created it.
type SelectiveRouteOptions struct {
	InterfaceName string
	Destinations  []netip.Prefix
	Excluded      []netip.Addr
}

// RouteTransaction owns the routes installed for one Core run. Close is
// idempotent and removes owned routes in reverse order.
type RouteTransaction interface {
	Close() error
}

type routeOperator interface {
	Add(context.Context, netip.Prefix) error
	Delete(context.Context, netip.Prefix) error
}

type routeTransaction struct {
	op        routeOperator
	installed []netip.Prefix
	closeOnce sync.Once
	closeErr  error
}

// InstallSelectiveRoutes validates and transactionally installs explicit game
// destination routes. It never installs a default route.
func InstallSelectiveRoutes(ctx context.Context, opts SelectiveRouteOptions) (RouteTransaction, error) {
	plan, err := PlanSelectiveRoutes(opts.Destinations, opts.Excluded)
	if err != nil {
		return nil, err
	}
	if len(plan) == 0 {
		return &routeTransaction{}, nil
	}
	if !SelectiveRoutesSupported() {
		return nil, ErrSelectiveRoutesUnsupported
	}
	op, err := newPlatformRouteOperator(opts.InterfaceName)
	if err != nil {
		return nil, err
	}
	return installRouteTransaction(ctx, op, plan)
}

// PlanSelectiveRoutes normalizes, de-duplicates, and checks explicit routes.
// Excluded addresses, especially every resolved Relay address, must remain on
// the physical network path.
func PlanSelectiveRoutes(destinations []netip.Prefix, excluded []netip.Addr) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(destinations))
	plan := make([]netip.Prefix, 0, len(destinations))
	for idx, prefix := range destinations {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("game destination route %d is invalid", idx)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("game destination route %s must not be a default route", prefix)
		}
		for _, addr := range excluded {
			addr = addr.Unmap()
			if addr.IsValid() && prefix.Contains(addr) {
				return nil, fmt.Errorf("%w: relay=%s route=%s", ErrRelayRouteConflict, addr, prefix)
			}
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		plan = append(plan, prefix)
	}
	return plan, nil
}

func installRouteTransaction(ctx context.Context, op routeOperator, plan []netip.Prefix) (*routeTransaction, error) {
	txn := &routeTransaction{op: op, installed: make([]netip.Prefix, 0, len(plan))}
	for _, prefix := range plan {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, txn.rollback())
		}
		if err := op.Add(ctx, prefix); err != nil {
			return nil, errors.Join(fmt.Errorf("install game destination route %s: %w", prefix, err), txn.rollback())
		}
		txn.installed = append(txn.installed, prefix)
	}
	return txn, nil
}

func (t *routeTransaction) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.rollback()
	})
	return t.closeErr
}

func (t *routeTransaction) rollback() error {
	if t.op == nil || len(t.installed) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), routeCleanupTimeout)
	defer cancel()

	var rollbackErr error
	for idx := len(t.installed) - 1; idx >= 0; idx-- {
		prefix := t.installed[idx]
		if err := t.op.Delete(ctx, prefix); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove game destination route %s: %w", prefix, err))
		}
	}
	t.installed = nil
	return rollbackErr
}
