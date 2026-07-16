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

const (
	routeCleanupTimeout  = 15 * time.Second
	routeReadbackTimeout = 5 * time.Second
)

var ErrRouteAlreadyExists = errors.New("route already exists")

// SelectiveRouteOptions describes destination routes owned by one Core run.
// Destinations are OS-level routes: every packet to these prefixes enters the
// TUN, regardless of which process created it.
type SelectiveRouteOptions struct {
	InterfaceName string
	InterfaceLUID uint64
	Destinations  []netip.Prefix
	Excluded      []netip.Addr
}

// RouteTransaction owns the routes installed for one Core run. Close is
// idempotent and removes owned routes in reverse order.
type RouteTransaction interface {
	Close() error
}

type routeOperator interface {
	Read(context.Context, netip.Prefix) (routeState, error)
	Add(context.Context, netip.Prefix) (routeAddResult, error)
	Delete(context.Context, netip.Prefix) (routeDeleteResult, error)
}

// routeAddResult reports whether the platform create API committed a new
// route. Callers must never infer ownership from readback after an error.
type routeAddResult struct {
	Committed bool
}

type routeDeleteResult struct {
	Committed bool
}

type routeState struct {
	Exists  bool
	Matches bool
}

type routeOwnershipStore interface {
	Reconcile(context.Context) error
	PrepareOwnership(netip.Prefix) error
	RecordOwnership(netip.Prefix) error
	PrepareDeletion(netip.Prefix) error
	ReleaseOwnership(netip.Prefix) error
}

type routeTransaction struct {
	op        routeOperator
	installed []netip.Prefix
	mu        sync.Mutex
}

// InstallSelectiveRoutes validates and transactionally installs explicit game
// destination routes. It never installs a default route.
func InstallSelectiveRoutes(ctx context.Context, opts SelectiveRouteOptions) (RouteTransaction, error) {
	plan, err := PlanSelectiveRoutes(opts.Destinations, opts.Excluded)
	if err != nil {
		return nil, err
	}
	if !SelectiveRoutesSupported() {
		if len(plan) == 0 {
			return &routeTransaction{}, nil
		}
		return nil, ErrSelectiveRoutesUnsupported
	}
	op, err := newPlatformRouteOperator(opts.InterfaceName, opts.InterfaceLUID)
	if err != nil {
		return nil, err
	}
	return installPlannedSelectiveRoutes(ctx, op, plan)
}

func installPlannedSelectiveRoutes(ctx context.Context, op routeOperator, plan []netip.Prefix) (RouteTransaction, error) {
	if store, ok := op.(routeOwnershipStore); ok {
		if err := store.Reconcile(ctx); err != nil {
			return nil, fmt.Errorf("reconcile selective route journal: %w", err)
		}
	}
	if len(plan) == 0 {
		return &routeTransaction{op: op}, nil
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
		baseline, err := op.Read(ctx, prefix)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("read baseline game destination route %s: %w", prefix, err), txn.rollback())
		}
		if baseline.Exists {
			if !baseline.Matches {
				return nil, errors.Join(fmt.Errorf("game destination route %s already exists with different attributes", prefix), txn.rollback())
			}
			continue
		}
		store, hasStore := op.(routeOwnershipStore)
		if hasStore {
			if err := store.PrepareOwnership(prefix); err != nil {
				return nil, errors.Join(fmt.Errorf("prepare route journal ownership %s: %w", prefix, err), txn.rollback())
			}
		}

		addResult, addErr := op.Add(ctx, prefix)
		if addResult.Committed {
			txn.installed = append(txn.installed, prefix)
			if hasStore {
				if err := store.RecordOwnership(prefix); err != nil {
					return nil, errors.Join(fmt.Errorf("journal owned game destination route %s: %w", prefix, err), addErr, txn.rollback())
				}
			}
		}
		readCtx, cancel := context.WithTimeout(context.Background(), routeReadbackTimeout)
		result, readErr := op.Read(readCtx, prefix)
		cancel()
		if !addResult.Committed && hasStore {
			if err := store.ReleaseOwnership(prefix); err != nil {
				return nil, errors.Join(fmt.Errorf("clear unowned route journal intent %s: %w", prefix, err), addErr, txn.rollback())
			}
		}
		if readErr != nil {
			return nil, errors.Join(fmt.Errorf("read back game destination route %s: %w", prefix, readErr), addErr, txn.rollback())
		}
		if addErr != nil {
			return nil, errors.Join(fmt.Errorf("install game destination route %s: %w", prefix, addErr), txn.rollback())
		}
		if !result.Matches {
			return nil, errors.Join(fmt.Errorf("game destination route %s did not match after installation", prefix), txn.rollback())
		}
	}
	return txn, nil
}

func (t *routeTransaction) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rollbackLocked()
}

func (t *routeTransaction) rollback() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rollbackLocked()
}

func (t *routeTransaction) rollbackLocked() error {
	if t.op == nil || len(t.installed) == 0 {
		return nil
	}

	var rollbackErr error
	remaining := make([]netip.Prefix, 0, len(t.installed))
	store, hasStore := t.op.(routeOwnershipStore)
	for idx := len(t.installed) - 1; idx >= 0; idx-- {
		prefix := t.installed[idx]
		if hasStore {
			if err := store.PrepareDeletion(prefix); err != nil {
				remaining = append(remaining, prefix)
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("prepare route journal deletion %s: %w", prefix, err))
				continue
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), routeCleanupTimeout)
		state, readErr := t.op.Read(ctx, prefix)
		if readErr != nil {
			cancel()
			remaining = append(remaining, prefix)
			if hasStore {
				rollbackErr = errors.Join(rollbackErr, store.RecordOwnership(prefix))
			}
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove game destination route %s: %w", prefix, readErr))
			continue
		}
		if !state.Matches {
			cancel()
			if hasStore {
				rollbackErr = errors.Join(rollbackErr, releaseRouteOwnership(store, prefix))
			}
			continue
		}

		deleteResult, deleteErr := t.op.Delete(ctx, prefix)
		cancel()
		if deleteResult.Committed || deleteErr == nil {
			if hasStore {
				rollbackErr = errors.Join(rollbackErr, releaseRouteOwnership(store, prefix))
			}
			continue
		}

		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), routeReadbackTimeout)
		result, verifyErr := t.op.Read(verifyCtx, prefix)
		verifyCancel()
		if verifyErr != nil {
			remaining = append(remaining, prefix)
		} else if result.Matches {
			remaining = append(remaining, prefix)
			if hasStore {
				rollbackErr = errors.Join(rollbackErr, store.RecordOwnership(prefix))
			}
		} else if hasStore {
			rollbackErr = errors.Join(rollbackErr, releaseRouteOwnership(store, prefix))
		}
		rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove game destination route %s: %w", prefix, errors.Join(deleteErr, verifyErr)))
	}
	for left, right := 0, len(remaining)-1; left < right; left, right = left+1, right-1 {
		remaining[left], remaining[right] = remaining[right], remaining[left]
	}
	t.installed = remaining
	return rollbackErr
}

func releaseRouteOwnership(store routeOwnershipStore, prefix netip.Prefix) error {
	if err := store.ReleaseOwnership(prefix); err != nil {
		return fmt.Errorf("release route journal ownership %s: %w", prefix, err)
	}
	return nil
}
