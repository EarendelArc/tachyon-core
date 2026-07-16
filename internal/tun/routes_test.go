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
	mu                   sync.Mutex
	routes               map[netip.Prefix]routeState
	addCalls             []netip.Prefix
	deleteCalls          []netip.Prefix
	deleteCtxs           []context.Context
	failAddAt            int
	addErr               error
	createOnErr          bool
	commitOnErr          bool
	deleteFails          map[netip.Prefix]int
	readAfterDeleteFails map[netip.Prefix]int
	recreate             map[netip.Prefix]routeState
}

type fakeOwnershipRouteOperator struct {
	*fakeRouteOperator
	reconcileCalls int
	ownership      map[netip.Prefix]string
}

func (f *fakeOwnershipRouteOperator) Reconcile(context.Context) error {
	f.reconcileCalls++
	return nil
}

func (f *fakeOwnershipRouteOperator) setOwnership(prefix netip.Prefix, state string) {
	if f.ownership == nil {
		f.ownership = make(map[netip.Prefix]string)
	}
	f.ownership[prefix] = state
}

func (f *fakeOwnershipRouteOperator) PrepareOwnership(_ context.Context, prefix netip.Prefix) error {
	f.setOwnership(prefix, windowsRoutePendingForTest)
	return nil
}

func (f *fakeOwnershipRouteOperator) RecordOwnership(prefix netip.Prefix) error {
	f.setOwnership(prefix, windowsRouteActiveForTest)
	return nil
}

func (f *fakeOwnershipRouteOperator) PrepareDeletion(_ context.Context, prefix netip.Prefix) error {
	f.setOwnership(prefix, windowsRouteDeletingForTest)
	return nil
}

func (f *fakeOwnershipRouteOperator) ReleaseOwnership(prefix netip.Prefix) error {
	delete(f.ownership, prefix)
	return nil
}

const (
	windowsRoutePendingForTest  = "pending"
	windowsRouteActiveForTest   = "active"
	windowsRouteDeletingForTest = "deleting"
)

func (f *fakeRouteOperator) Read(ctx context.Context, prefix netip.Prefix) (routeState, error) {
	if err := ctx.Err(); err != nil {
		return routeState{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readAfterDeleteFails[prefix] > 0 {
		for _, deleted := range f.deleteCalls {
			if deleted == prefix {
				f.readAfterDeleteFails[prefix]--
				return routeState{}, errors.New("injected read-after-delete failure")
			}
		}
	}
	return f.routes[prefix], nil
}

func (f *fakeRouteOperator) Add(ctx context.Context, prefix netip.Prefix) (routeAddResult, error) {
	if err := ctx.Err(); err != nil {
		return routeAddResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls = append(f.addCalls, prefix)
	if f.failAddAt > 0 && len(f.addCalls) == f.failAddAt {
		if f.createOnErr {
			f.setRoute(prefix, routeState{Exists: true, Matches: true})
		}
		if f.addErr != nil {
			return routeAddResult{Committed: f.commitOnErr}, f.addErr
		}
		return routeAddResult{Committed: f.commitOnErr}, errors.New("injected add failure")
	}
	f.setRoute(prefix, routeState{Exists: true, Matches: true})
	return routeAddResult{Committed: true}, nil
}

func (f *fakeRouteOperator) Delete(ctx context.Context, prefix netip.Prefix) (routeDeleteResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, prefix)
	f.deleteCtxs = append(f.deleteCtxs, ctx)
	if f.deleteFails[prefix] > 0 {
		f.deleteFails[prefix]--
		return routeDeleteResult{}, errors.New("injected delete failure")
	}
	delete(f.routes, prefix)
	if replacement, ok := f.recreate[prefix]; ok {
		f.setRoute(prefix, replacement)
	}
	return routeDeleteResult{Committed: true}, nil
}

func (f *fakeRouteOperator) setRoute(prefix netip.Prefix, state routeState) {
	if f.routes == nil {
		f.routes = make(map[netip.Prefix]routeState)
	}
	f.routes[prefix] = state
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

func TestEmptySelectiveRoutePlanStillReconcilesOwnership(t *testing.T) {
	op := &fakeOwnershipRouteOperator{fakeRouteOperator: &fakeRouteOperator{}}
	txn, err := installPlannedSelectiveRoutes(context.Background(), op, nil)
	if err != nil {
		t.Fatal(err)
	}
	if op.reconcileCalls != 1 {
		t.Fatalf("reconcile calls = %d, want 1", op.reconcileCalls)
	}
	if err := txn.Close(); err != nil {
		t.Fatal(err)
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

func TestInstallRouteTransactionOwnsAndRollsBackAddThatTimedOutAfterCreation(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	op := &fakeRouteOperator{
		failAddAt:   1,
		addErr:      context.DeadlineExceeded,
		createOnErr: true,
		commitOnErr: true,
	}

	_, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if !reflect.DeepEqual(op.deleteCalls, []netip.Prefix{prefix}) {
		t.Fatalf("created route was not rolled back: %v", op.deleteCalls)
	}
}

func TestInstallRouteTransactionDoesNotOwnMatchingReadbackAfterOrdinaryAddError(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	op := &fakeRouteOperator{
		failAddAt:   1,
		addErr:      errors.New("create failed while another actor added the route"),
		createOnErr: true,
	}

	if _, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix}); err == nil {
		t.Fatal("expected add failure")
	}
	if len(op.deleteCalls) != 0 {
		t.Fatalf("matching concurrent route was treated as owned: %v", op.deleteCalls)
	}
}

func TestInstallRouteTransactionPreservesBaselineRoute(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	op := &fakeRouteOperator{routes: map[netip.Prefix]routeState{
		prefix: {Exists: true, Matches: true},
	}}
	txn, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix})
	if err != nil {
		t.Fatal(err)
	}
	if err := txn.Close(); err != nil {
		t.Fatal(err)
	}
	if len(op.addCalls) != 0 || len(op.deleteCalls) != 0 {
		t.Fatalf("baseline route was mutated: add=%v delete=%v", op.addCalls, op.deleteCalls)
	}
}

func TestInstallRouteTransactionDoesNotOwnConcurrentExistingRoute(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	op := &fakeRouteOperator{
		failAddAt:   1,
		addErr:      ErrRouteAlreadyExists,
		createOnErr: true,
	}
	if _, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix}); !errors.Is(err, ErrRouteAlreadyExists) {
		t.Fatalf("error = %v, want route already exists", err)
	}
	if len(op.deleteCalls) != 0 {
		t.Fatalf("concurrently created route was deleted: %v", op.deleteCalls)
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

func TestRouteTransactionCloseRetriesFailedDeletes(t *testing.T) {
	first := netip.MustParsePrefix("192.0.2.0/24")
	second := netip.MustParsePrefix("198.51.100.0/24")
	op := &fakeRouteOperator{
		routes: map[netip.Prefix]routeState{
			first:  {Exists: true, Matches: true},
			second: {Exists: true, Matches: true},
		},
		deleteFails: map[netip.Prefix]int{first: 1, second: 1},
	}
	txn := &routeTransaction{
		op:        op,
		installed: []netip.Prefix{first, second},
	}
	if err := txn.Close(); err == nil {
		t.Fatal("first close should report both delete failures")
	}
	if err := txn.Close(); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if err := txn.Close(); err != nil {
		t.Fatalf("completed close should be idempotent: %v", err)
	}
	if len(op.deleteCalls) != 4 {
		t.Fatalf("delete calls = %d, want each failed route retried once", len(op.deleteCalls))
	}
	if len(op.deleteCtxs) < 2 || op.deleteCtxs[0] == op.deleteCtxs[1] {
		t.Fatal("route deletes did not receive independent timeout contexts")
	}
	for idx, ctx := range op.deleteCtxs {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatalf("delete context %d has no deadline", idx)
		}
	}
}

func TestRouteTransactionPreservesDeletingOwnershipAfterDeleteAndReadFailures(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	op := &fakeOwnershipRouteOperator{
		fakeRouteOperator: &fakeRouteOperator{
			routes:               map[netip.Prefix]routeState{prefix: {Exists: true, Matches: true}},
			deleteFails:          map[netip.Prefix]int{prefix: 1},
			readAfterDeleteFails: map[netip.Prefix]int{prefix: 1},
		},
		ownership: map[netip.Prefix]string{prefix: windowsRouteActiveForTest},
	}
	txn := &routeTransaction{op: op, installed: []netip.Prefix{prefix}}

	if err := txn.Close(); err == nil {
		t.Fatal("first close should report delete and readback failures")
	}
	if !reflect.DeepEqual(txn.installed, []netip.Prefix{prefix}) {
		t.Fatalf("remaining routes = %v, want owned route retained", txn.installed)
	}
	if state := op.ownership[prefix]; state != windowsRouteDeletingForTest {
		t.Fatalf("journal ownership state = %q, want deleting", state)
	}
	if err := txn.Close(); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if len(txn.installed) != 0 {
		t.Fatalf("remaining routes after retry = %v", txn.installed)
	}
	if _, ok := op.ownership[prefix]; ok {
		t.Fatal("committed retry did not release journal ownership")
	}
}

func TestRouteTransactionConcurrentCloseSerializesOwnership(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	op := &fakeRouteOperator{routes: map[netip.Prefix]routeState{
		prefix: {Exists: true, Matches: true},
	}}
	txn := &routeTransaction{op: op, installed: []netip.Prefix{prefix}}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- txn.Close()
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(op.deleteCalls) != 1 {
		t.Fatalf("concurrent Close deleted route %d times", len(op.deleteCalls))
	}
}

func TestRouteTransactionDeleteSuccessAbandonsRecreatedMatchingRoute(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	op := &fakeRouteOperator{
		routes:   map[netip.Prefix]routeState{prefix: {Exists: true, Matches: true}},
		recreate: map[netip.Prefix]routeState{prefix: {Exists: true, Matches: true}},
	}
	txn := &routeTransaction{op: op, installed: []netip.Prefix{prefix}}

	if err := txn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := txn.Close(); err != nil {
		t.Fatal(err)
	}
	if len(op.deleteCalls) != 1 {
		t.Fatalf("recreated replacement was deleted on a later Close: %v", op.deleteCalls)
	}
}
