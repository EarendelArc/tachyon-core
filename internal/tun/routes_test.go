package tun

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

type fakeRouteOperator struct {
	mu          sync.Mutex
	addCalls    []netip.Prefix
	deleteCalls []netip.Prefix
	failAddAt   int
	deleteErr   error
}

func (f *fakeRouteOperator) Add(ctx context.Context, prefix netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls = append(f.addCalls, prefix)
	if f.failAddAt > 0 && len(f.addCalls) == f.failAddAt {
		return errors.New("injected add failure")
	}
	return nil
}

func (f *fakeRouteOperator) Delete(_ context.Context, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, prefix)
	return f.deleteErr
}

func TestPlanSelectiveRoutesNormalizesAndDeduplicates(t *testing.T) {
	plan, err := PlanSelectiveRoutes([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.42/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:1::5/64"),
	}, []netip.Addr{netip.MustParseAddr("198.51.100.10")})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:1::/64"),
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("plan = %v, want %v", plan, want)
	}
}

func TestPlanSelectiveRoutesRejectsDefaultRoutes(t *testing.T) {
	for _, raw := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := PlanSelectiveRoutes([]netip.Prefix{netip.MustParsePrefix(raw)}, nil); err == nil {
			t.Fatalf("expected %s to be rejected", raw)
		}
	}
}

func TestPlanSelectiveRoutesRejectsRelayOverlap(t *testing.T) {
	_, err := PlanSelectiveRoutes(
		[]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		[]netip.Addr{netip.MustParseAddr("203.0.113.9")},
	)
	if !errors.Is(err, ErrRelayRouteConflict) {
		t.Fatalf("error = %v, want ErrRelayRouteConflict", err)
	}
}

func TestInstallRouteTransactionRollsBackInReverseOrder(t *testing.T) {
	op := &fakeRouteOperator{failAddAt: 3}
	plan := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	if _, err := installRouteTransaction(context.Background(), op, plan); err == nil {
		t.Fatal("expected injected failure")
	}
	wantDeletes := []netip.Prefix{plan[1], plan[0]}
	if !reflect.DeepEqual(op.deleteCalls, wantDeletes) {
		t.Fatalf("delete calls = %v, want %v", op.deleteCalls, wantDeletes)
	}
}

func TestInstallRouteTransactionDoesNotDeleteFailedFirstAdd(t *testing.T) {
	op := &fakeRouteOperator{failAddAt: 1}
	prefix := netip.MustParsePrefix("192.0.2.0/24")

	if _, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix}); err == nil {
		t.Fatal("expected injected failure")
	}
	if len(op.deleteCalls) != 0 {
		t.Fatalf("failed Add must not establish ownership: delete calls = %v", op.deleteCalls)
	}
}

func TestInstallRouteTransactionCanceledContextRollsBack(t *testing.T) {
	op := &fakeRouteOperator{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := installRouteTransaction(ctx, op, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(op.addCalls) != 0 || len(op.deleteCalls) != 0 {
		t.Fatalf("canceled install mutated routes: add=%v delete=%v", op.addCalls, op.deleteCalls)
	}
}

func TestRouteTransactionCloseIsIdempotentAndReportsCleanup(t *testing.T) {
	op := &fakeRouteOperator{deleteErr: errors.New("injected delete failure")}
	txn := &routeTransaction{
		op: op,
		installed: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("198.51.100.0/24"),
		},
	}
	first := txn.Close()
	second := txn.Close()
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("idempotent errors = %v / %v", first, second)
	}
	if len(op.deleteCalls) != 2 {
		t.Fatalf("delete calls = %d, want 2", len(op.deleteCalls))
	}
}
