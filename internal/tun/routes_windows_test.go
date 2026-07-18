//go:build windows

package tun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestWindowsRouteIdentitySurvivesInterfaceRename(t *testing.T) {
	api := windowsRouteAPI{initEntry: func(*windows.MibIpForwardRow2) {}}
	before := (&windowsRouteOperator{
		interfaceName: "Tachyon",
		interfaceLUID: 0x12345678,
		interfaceIdx:  42,
		api:           api,
	}).routeRow(netip.MustParsePrefix("203.0.113.0/24"))
	after := (&windowsRouteOperator{
		interfaceName: "Renamed by user",
		interfaceLUID: 0x12345678,
		interfaceIdx:  42,
		api:           api,
	}).routeRow(netip.MustParsePrefix("203.0.113.0/24"))
	if !windowsRouteRowsMatch(before, after) {
		t.Fatalf("interface rename changed route identity: before=%+v after=%+v", before, after)
	}
}

func TestWindowsTUNAddressesUseActiveStore(t *testing.T) {
	for _, raw := range []string{"198.18.0.1/16", "2001:db8::1/64"} {
		args, err := windowsAddressArgs("Tachyon", netip.MustParsePrefix(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(args, "store=active") {
			t.Fatalf("address args for %s omit store=active: %v", raw, args)
		}
	}
}

func TestWindowsRouteRowsRequireExactIdentityAndAttributes(t *testing.T) {
	op := &windowsRouteOperator{
		interfaceLUID: 9,
		interfaceIdx:  7,
		api:           windowsRouteAPI{initEntry: func(*windows.MibIpForwardRow2) {}},
	}
	want := op.routeRow(netip.MustParsePrefix("2001:db8:1::/64"))
	got := want
	got.Metric++
	if windowsRouteRowsMatch(got, want) {
		t.Fatal("route with a different metric matched")
	}
	got = want
	got.InterfaceLuid++
	if windowsRouteRowsMatch(got, want) {
		t.Fatal("route on a different interface LUID matched")
	}
}

func TestWindowsRouteJournalReconcilesOnlyExactStableIdentity(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	otherPrefix := netip.MustParsePrefix("198.51.100.0/24")
	rows := make(map[string]windows.MibIpForwardRow2)
	deleted := make([]string, 0, 1)
	op := &windowsRouteOperator{
		interfaceName: "renamed",
		interfaceLUID: 55,
		interfaceIdx:  12,
	}
	op.api = windowsRouteAPI{
		initEntry: func(*windows.MibIpForwardRow2) {},
		get: func(row *windows.MibIpForwardRow2) error {
			stored, ok := rows[windowsRouteRowKey(*row)]
			if !ok {
				return windows.ERROR_NOT_FOUND
			}
			*row = stored
			return nil
		},
		delete: func(row *windows.MibIpForwardRow2) error {
			key := windowsRouteRowKey(*row)
			deleted = append(deleted, key)
			delete(rows, key)
			return nil
		},
	}
	owned := op.routeRow(prefix)
	rows[windowsRouteRowKey(owned)] = owned
	other := op.routeRow(otherPrefix)
	other.InterfaceLuid = 99
	rows[windowsRouteRowKey(other)] = other

	journal := newWindowsRouteJournalForTest()
	op.journal = journal
	ownedEntry := testWindowsRouteJournalEntry(t, op, prefix, windowsRouteActive)
	otherOp := *op
	otherOp.interfaceLUID = 99
	otherEntry := testWindowsRouteJournalEntry(t, &otherOp, otherPrefix, windowsRouteActive)
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{ownedEntry, otherEntry},
	}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != windowsRouteRowKey(owned) {
		t.Fatalf("deleted rows = %v, want only exact owned route", deleted)
	}
	data, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 1 || data.Entries[0].InterfaceLUID != 99 {
		t.Fatalf("journal entries after reconcile = %+v", data.Entries)
	}
}

func TestWindowsRouteJournalKeepsLiveForeignLUIDOwnerFailClosed(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	foreign := &windowsRouteOperator{interfaceLUID: 99, interfaceIdx: 14}
	journal := newWindowsRouteJournalForTest()
	entry := testWindowsRouteJournalEntry(t, foreign, prefix, windowsRouteActive)
	if err := journal.save(windowsRouteJournalData{Version: windowsRouteJournalVersion, Entries: []windowsRouteJournalEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry:       func(*windows.MibIpForwardRow2) {},
			interfaceExists: func(luid uint64, index uint32) (bool, error) { return luid == 99 && index == 14, nil },
			get: func(*windows.MibIpForwardRow2) error {
				t.Fatal("live foreign owner route must not be inspected or deleted")
				return nil
			},
			delete: func(*windows.MibIpForwardRow2) error {
				t.Fatal("live foreign owner route must not be deleted")
				return nil
			},
		},
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 1 || data.Entries[0].InterfaceLUID != 99 {
		t.Fatalf("live foreign ownership changed: data=%+v error=%v", data, err)
	}
}

func TestWindowsRouteJournalCleansStaleForeignLUIDAndAllowsNewOwner(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	foreign := &windowsRouteOperator{
		interfaceLUID: 99,
		interfaceIdx:  14,
		api:           windowsRouteAPI{initEntry: func(*windows.MibIpForwardRow2) {}},
	}
	row := foreign.routeRow(prefix)
	rows := map[string]windows.MibIpForwardRow2{windowsRouteRowKey(row): row}
	deleteCalls := 0
	journal := newWindowsRouteJournalForTest()
	entry := testWindowsRouteJournalEntry(t, foreign, prefix, windowsRouteActive)
	if err := journal.save(windowsRouteJournalData{Version: windowsRouteJournalVersion, Entries: []windowsRouteJournalEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry:       func(*windows.MibIpForwardRow2) {},
			interfaceExists: func(uint64, uint32) (bool, error) { return false, nil },
			get: func(got *windows.MibIpForwardRow2) error {
				stored, ok := rows[windowsRouteRowKey(*got)]
				if !ok {
					return windows.ERROR_NOT_FOUND
				}
				*got = stored
				return nil
			},
			delete: func(got *windows.MibIpForwardRow2) error {
				deleteCalls++
				delete(rows, windowsRouteRowKey(*got))
				return nil
			},
		},
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 0 || deleteCalls != 1 {
		t.Fatalf("stale foreign cleanup data=%+v deleteCalls=%d error=%v", data, deleteCalls, err)
	}
	if err := journal.prepare(context.Background(), op, prefix); err != nil {
		t.Fatalf("new LUID could not claim cleaned stale destination: %v", err)
	}
	if err := journal.release(op, prefix); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsRouteJournalForeignLUIDQueryFailureIsFailClosed(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	foreign := &windowsRouteOperator{interfaceLUID: 99, interfaceIdx: 14}
	journal := newWindowsRouteJournalForTest()
	entry := testWindowsRouteJournalEntry(t, foreign, prefix, windowsRouteDeleting)
	if err := journal.save(windowsRouteJournalData{Version: windowsRouteJournalVersion, Entries: []windowsRouteJournalEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			interfaceExists: func(uint64, uint32) (bool, error) {
				return false, windows.ERROR_RETRY
			},
			delete: func(*windows.MibIpForwardRow2) error {
				t.Fatal("uncertain foreign owner must not drive deletion")
				return nil
			},
		},
	}
	if err := op.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "query foreign route owner") {
		t.Fatalf("foreign owner query error = %v", err)
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 1 || data.Entries[0].State != windowsRouteDeleting {
		t.Fatalf("query failure changed fail-closed ownership: data=%+v error=%v", data, err)
	}
}

func TestWindowsRouteJournalAbandonsChangedReplacement(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
		},
	}
	changed := op.routeRow(prefix)
	changed.Metric++
	op.api.get = func(row *windows.MibIpForwardRow2) error {
		*row = changed
		return nil
	}
	op.api.delete = func(*windows.MibIpForwardRow2) error {
		t.Fatal("changed route must not be deleted")
		return nil
	}
	journal := newWindowsRouteJournalForTest()
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{testWindowsRouteJournalEntry(t, op, prefix, windowsRouteActive)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 0 {
		t.Fatalf("changed replacement remained owned: %+v", data.Entries)
	}
}

func TestWindowsRouteJournalRecoversPendingCreateByExactSignature(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
		},
	}
	row := op.routeRow(prefix)
	op.api.get = func(got *windows.MibIpForwardRow2) error {
		*got = row
		return nil
	}
	deleteCalls := 0
	op.api.delete = func(got *windows.MibIpForwardRow2) error {
		deleteCalls++
		if !windowsRouteRowsMatch(*got, row) {
			t.Fatalf("deleted row = %+v, want exact pending signature %+v", *got, row)
		}
		return nil
	}
	journal := newWindowsRouteJournalForTest()
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{testWindowsRouteJournalEntry(t, op, prefix, windowsRoutePending)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 0 || deleteCalls != 1 {
		t.Fatalf("pending create recovery left entries=%+v deleteCalls=%d", data.Entries, deleteCalls)
	}
}

func TestWindowsRouteJournalReleasesPendingWhenOnlySamePrefixForeignSignatureExists(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	op := &windowsRouteOperator{interfaceLUID: 55, interfaceIdx: 12, api: windowsRouteAPI{initEntry: func(*windows.MibIpForwardRow2) {}}}
	foreign := op.routeRowWithMetric(prefix, 9001)
	op.api.get = func(got *windows.MibIpForwardRow2) error {
		*got = foreign
		return nil
	}
	op.api.delete = func(*windows.MibIpForwardRow2) error {
		t.Fatal("same-prefix route with a different signature must not be deleted")
		return nil
	}
	journal := newWindowsRouteJournalForTest()
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{Version: windowsRouteJournalVersion, Entries: []windowsRouteJournalEntry{
		testWindowsRouteJournalEntry(t, op, prefix, windowsRoutePending),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 0 {
		t.Fatalf("absent pending signature was not released: %+v", data.Entries)
	}
}

func TestWindowsRouteJournalRecoversCrashAfterCreateBeforeRecordOwnership(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	journal := newWindowsRouteJournalForTest()
	var created *windows.MibIpForwardRow2
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get: func(got *windows.MibIpForwardRow2) error {
				if created == nil {
					return windows.ERROR_NOT_FOUND
				}
				*got = *created
				return nil
			},
			create: func(row *windows.MibIpForwardRow2) error {
				copy := *row
				created = &copy
				return nil
			},
		},
	}
	if err := journal.prepare(context.Background(), op, prefix); err != nil {
		t.Fatal(err)
	}
	if result, err := op.Add(context.Background(), prefix); err != nil || !result.Committed {
		t.Fatalf("create result=%+v error=%v", result, err)
	}
	if created.Metric != windowsRouteMetric {
		t.Fatalf("created route metric = %d, want fixed production metric %d", created.Metric, windowsRouteMetric)
	}
	prepared, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Entries) != 1 || prepared.Entries[0].TransactionID == "" {
		t.Fatalf("pending journal does not contain a transaction ID: %+v", prepared.Entries)
	}

	// Simulate process termination after CreateIpForwardEntry2 and before RecordOwnership.
	transition := op.transition
	op.transition = nil
	if err := transition.lock.unlock(); err != nil {
		t.Fatal(err)
	}

	deleteCalls := 0
	recovery := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get: func(got *windows.MibIpForwardRow2) error {
				*got = *created
				return nil
			},
			delete: func(row *windows.MibIpForwardRow2) error {
				deleteCalls++
				if !windowsRouteRowsMatch(*row, *created) {
					t.Fatalf("recovery deleted non-signature row: got=%+v want=%+v", *row, *created)
				}
				return nil
			},
		},
	}
	if err := recovery.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if deleteCalls != 1 || len(data.Entries) != 0 {
		t.Fatalf("crash recovery deleteCalls=%d entries=%+v", deleteCalls, data.Entries)
	}
}

func TestWindowsRouteJournalRejectsDestinationOwnedByDifferentLUID(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	journal := newWindowsRouteJournalForTest()
	owner := &windowsRouteOperator{interfaceLUID: 55, interfaceIdx: 12}
	entry := testWindowsRouteJournalEntry(t, owner, prefix, windowsRouteActive)
	if err := journal.save(windowsRouteJournalData{Version: windowsRouteJournalVersion, Entries: []windowsRouteJournalEntry{entry}}); err != nil {
		t.Fatal(err)
	}

	contender := &windowsRouteOperator{
		interfaceLUID: 99,
		interfaceIdx:  13,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get:       func(*windows.MibIpForwardRow2) error { return windows.ERROR_NOT_FOUND },
		},
	}
	if err := journal.prepare(context.Background(), contender, prefix); err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("different-LUID destination claim error = %v", err)
	}
	if contender.transition != nil {
		t.Fatal("rejected destination claim retained a transition")
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 1 || data.Entries[0].InterfaceLUID != owner.interfaceLUID {
		t.Fatalf("rejected claim changed ownership: data=%+v error=%v", data, err)
	}
}

func TestWindowsRouteJournalRecordFailureRollsBackCreatedRouteUnderLock(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	storage := &memoryWindowsRouteJournalStorage{writeErrors: map[int]error{2: errors.New("injected active persistence failure")}}
	locker := &observedLocalWindowsRouteJournalLocker{}
	journal := &windowsRouteJournal{storage: storage, locker: locker}
	var route *windows.MibIpForwardRow2
	deleteCalls := 0
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get: func(row *windows.MibIpForwardRow2) error {
				if route == nil {
					return windows.ERROR_NOT_FOUND
				}
				*row = *route
				return nil
			},
			create: func(row *windows.MibIpForwardRow2) error {
				copy := *row
				route = &copy
				return nil
			},
			delete: func(*windows.MibIpForwardRow2) error {
				if !locker.held {
					t.Fatal("RecordOwnership rollback deleted outside the machine journal lock")
				}
				deleteCalls++
				route = nil
				return nil
			},
		},
	}

	_, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix})
	if err == nil || !strings.Contains(err.Error(), "persist active route ownership") {
		t.Fatalf("install error = %v", err)
	}
	if route != nil || deleteCalls != 1 {
		t.Fatalf("failed active record left route=%+v deleteCalls=%d", route, deleteCalls)
	}
	data, loadErr := journal.load()
	if loadErr != nil || len(data.Entries) != 0 {
		t.Fatalf("failed active record left journal=%+v error=%v", data, loadErr)
	}
	if locker.held {
		t.Fatal("failed active record left machine journal lock held")
	}
}

func TestWindowsRouteJournalRecordFailureRemovesRouteWhenIntentCleanupAlsoFails(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.1/32")
	storage := &memoryWindowsRouteJournalStorage{writeErrors: map[int]error{
		2: errors.New("injected active persistence failure"),
		3: errors.New("injected intent cleanup failure"),
	}}
	journal := &windowsRouteJournal{storage: storage, locker: &localWindowsRouteJournalLocker{}}
	var route *windows.MibIpForwardRow2
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get: func(row *windows.MibIpForwardRow2) error {
				if route == nil {
					return windows.ERROR_NOT_FOUND
				}
				*row = *route
				return nil
			},
			create: func(row *windows.MibIpForwardRow2) error {
				copy := *row
				route = &copy
				return nil
			},
			delete: func(*windows.MibIpForwardRow2) error {
				route = nil
				return nil
			},
		},
	}

	if _, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix}); err == nil || !strings.Contains(err.Error(), "intent cleanup failure") {
		t.Fatalf("install error = %v", err)
	}
	if route != nil {
		t.Fatal("failed intent cleanup left the just-created route installed")
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 1 || data.Entries[0].State != windowsRoutePending {
		t.Fatalf("cleanup failure must retain fail-closed pending intent: data=%+v error=%v", data, err)
	}
}

func TestWindowsRouteJournalRecordFailureRetainsPendingWhenImmediateDeleteFails(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.2/32")
	storage := &memoryWindowsRouteJournalStorage{writeErrors: map[int]error{2: errors.New("injected active persistence failure")}}
	journal := &windowsRouteJournal{storage: storage, locker: &localWindowsRouteJournalLocker{}}
	var route *windows.MibIpForwardRow2
	deleteCalls := 0
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get: func(row *windows.MibIpForwardRow2) error {
				if route == nil {
					return windows.ERROR_NOT_FOUND
				}
				*row = *route
				return nil
			},
			create: func(row *windows.MibIpForwardRow2) error {
				copy := *row
				route = &copy
				return nil
			},
			delete: func(*windows.MibIpForwardRow2) error {
				deleteCalls++
				return windows.ERROR_RETRY
			},
		},
	}

	if _, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix}); err == nil || !strings.Contains(err.Error(), "delete route during failed active ownership rollback") {
		t.Fatalf("install error = %v", err)
	}
	if route == nil || deleteCalls != 1 {
		t.Fatalf("failed immediate delete route=%+v deleteCalls=%d", route, deleteCalls)
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 1 || data.Entries[0].State != windowsRoutePending {
		t.Fatalf("failed immediate delete must retain pending ownership: data=%+v error=%v", data, err)
	}
}

func TestWindowsRouteJournalDeleteSuccessAbandonsRecreatedRoute(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	rows := make(map[string]windows.MibIpForwardRow2)
	deleteCalls := 0
	op := &windowsRouteOperator{interfaceLUID: 55, interfaceIdx: 12}
	op.api = windowsRouteAPI{
		initEntry: func(*windows.MibIpForwardRow2) {},
		get: func(row *windows.MibIpForwardRow2) error {
			stored, ok := rows[windowsRouteRowKey(*row)]
			if !ok {
				return windows.ERROR_NOT_FOUND
			}
			*row = stored
			return nil
		},
		delete: func(row *windows.MibIpForwardRow2) error {
			deleteCalls++
			key := windowsRouteRowKey(*row)
			delete(rows, key)
			rows[key] = op.routeRow(prefix)
			return nil
		},
	}
	owned := op.routeRow(prefix)
	rows[windowsRouteRowKey(owned)] = owned
	journal := newWindowsRouteJournalForTest()
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{testWindowsRouteJournalEntry(t, op, prefix, windowsRouteActive)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if deleteCalls != 1 {
		t.Fatalf("recreated route was deleted %d times", deleteCalls)
	}
}

func TestWindowsRouteJournalRetriesDeletingEntryAfterDeleteAndReadFailures(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	journal := newWindowsRouteJournalForTest()
	getCalls := 0
	deleteCalls := 0
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api:           windowsRouteAPI{initEntry: func(*windows.MibIpForwardRow2) {}},
	}
	row := op.routeRow(prefix)
	op.api = windowsRouteAPI{
		initEntry: func(*windows.MibIpForwardRow2) {},
		get: func(got *windows.MibIpForwardRow2) error {
			getCalls++
			if getCalls == 3 {
				return windows.ERROR_RETRY
			}
			*got = row
			return nil
		},
		delete: func(*windows.MibIpForwardRow2) error {
			deleteCalls++
			if deleteCalls == 1 {
				return windows.ERROR_RETRY
			}
			return nil
		},
	}
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{testWindowsRouteJournalEntry(t, op, prefix, windowsRouteDeleting)},
	}); err != nil {
		t.Fatal(err)
	}

	if err := op.Reconcile(context.Background()); err == nil {
		t.Fatal("first reconcile should report delete and readback failures")
	}
	data, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 1 || data.Entries[0].State != windowsRouteDeleting {
		t.Fatalf("journal after double failure = %+v, want deleting entry retained", data.Entries)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	data, err = journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 0 || deleteCalls != 2 {
		t.Fatalf("retry left entries=%+v deleteCalls=%d", data.Entries, deleteCalls)
	}
}

func TestWindowsRouteJournalCorruptionCannotDriveDelete(t *testing.T) {
	journal := newWindowsRouteJournalForTest()
	journal.storage.(*memoryWindowsRouteJournalStorage).value = []byte(`{"version":2,"entries":[`)
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			delete: func(*windows.MibIpForwardRow2) error {
				t.Fatal("corrupt journal must not drive route deletion")
				return nil
			},
		},
	}
	if err := op.Reconcile(context.Background()); err == nil {
		t.Fatal("corrupt journal should fail closed")
	}
}

func TestWindowsRouteJournalFailsClosedWithoutCurrentAdapterOwnership(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.77/32")
	op := &windowsRouteOperator{
		interfaceLUID: 55,
		interfaceIdx:  12,
		adapterOwned:  func() bool { return false },
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			delete: func(*windows.MibIpForwardRow2) error {
				t.Fatal("unowned adapter must not drive route deletion")
				return nil
			},
		},
	}
	journal := newWindowsRouteJournalForTest()
	op.journal = journal
	entry := testWindowsRouteJournalEntry(t, op, prefix, windowsRoutePending)
	if err := journal.save(windowsRouteJournalData{Version: windowsRouteJournalVersion, Entries: []windowsRouteJournalEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("adapter ownership error = %v", err)
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 1 {
		t.Fatalf("fail-closed recovery changed journal: data=%+v error=%v", data, err)
	}
}

func TestWindowsRegistryBinaryReadRejectsTwoPhaseValueChanges(t *testing.T) {
	tests := []struct {
		name       string
		secondSize uint32
		secondErr  error
	}{
		{name: "shrinks", secondSize: 3},
		{name: "grows", secondSize: 8, secondErr: windows.ERROR_MORE_DATA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			_, err := readBoundedWindowsRegistryBinaryValue(func(valueType *uint32, data *byte, size *uint32) error {
				calls++
				*valueType = registry.BINARY
				if calls == 1 {
					*size = 4
					return nil
				}
				*size = tt.secondSize
				return tt.secondErr
			})
			if err == nil {
				t.Fatal("two-phase registry value change was accepted")
			}
		})
	}
}

func TestDefaultWindowsRouteJournalUsesFixedMachineRegistryKey(t *testing.T) {
	t.Setenv("TACHYON_ROUTE_JOURNAL", filepath.Join(t.TempDir(), "forged.json"))
	storage := defaultWindowsRouteJournalStorage()
	if storage.root != registry.LOCAL_MACHINE || storage.keyPath != windowsRouteJournalKey || storage.valueName != windowsRouteJournalValue {
		t.Fatalf("registry location = root %v path %q value %q", storage.root, storage.keyPath, storage.valueName)
	}
}

func TestWindowsRouteJournalWritesWholeAtomicStatesAndCleansUp(t *testing.T) {
	journal := newWindowsRouteJournalForTest()
	storage := journal.storage.(*memoryWindowsRouteJournalStorage)
	op := &windowsRouteOperator{interfaceLUID: 55, interfaceIdx: 12, journal: journal}
	prefix := netip.MustParsePrefix("203.0.113.0/24")

	op.api = windowsRouteAPI{
		initEntry: func(*windows.MibIpForwardRow2) {},
		get:       func(*windows.MibIpForwardRow2) error { return windows.ERROR_NOT_FOUND },
	}
	if err := journal.prepare(context.Background(), op, prefix); err != nil {
		t.Fatal(err)
	}
	if err := journal.record(op, prefix); err != nil {
		t.Fatal(err)
	}
	if err := journal.prepareDeletion(context.Background(), op, prefix); err != nil {
		t.Fatal(err)
	}
	for idx, wantState := range []string{windowsRoutePending, windowsRouteActive, windowsRouteDeleting} {
		var data windowsRouteJournalData
		if err := json.Unmarshal(storage.writes[idx], &data); err != nil {
			t.Fatalf("atomic write %d is not complete JSON: %v", idx, err)
		}
		if len(data.Entries) != 1 || data.Entries[0].State != wantState {
			t.Fatalf("atomic write %d = %+v, want state %q", idx, data, wantState)
		}
		if !data.Entries[0].BaselineAbsent || data.Entries[0].Metric != windowsRouteMetric || data.Entries[0].TransactionID == "" {
			t.Fatalf("atomic write %d lacks absent baseline or route signature: %+v", idx, data.Entries[0])
		}
	}
	if err := journal.release(op, prefix); err != nil {
		t.Fatal(err)
	}
	var empty windowsRouteJournalData
	if err := json.Unmarshal(storage.value, &empty); err != nil || empty.Version != windowsRouteJournalVersion || len(empty.Entries) != 0 {
		t.Fatalf("empty journal was not retained as valid state: data=%+v error=%v", empty, err)
	}
}

func TestWindowsRouteJournalSecurityDescriptorRequiresProtectedTrustedACL(t *testing.T) {
	creationDescriptor, err := newWindowsRouteJournalSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsJournalSecurityDescriptor(creationDescriptor); err != nil {
		t.Fatalf("atomic registry creation descriptor is not trusted: %v", err)
	}
	mutexDescriptor, err := newWindowsRouteMutexSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsTrustedACL(mutexDescriptor, windows.MUTEX_ALL_ACCESS, "mutex"); err != nil {
		t.Fatalf("Global mutex creation descriptor is not trusted: %v", err)
	}
	namespaceDescriptor, err := newWindowsRouteNamespaceSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsTrustedACL(namespaceDescriptor, windows.GENERIC_ALL, "private namespace"); err != nil {
		t.Fatalf("private namespace creation descriptor is not trusted: %v", err)
	}

	tests := []struct {
		name    string
		sddl    string
		wantErr bool
	}{
		{name: "protected system and admins", sddl: "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)"},
		{name: "system owner", sddl: "O:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)", wantErr: true},
		{name: "inheritance enabled", sddl: "O:SYD:(A;;KA;;;SY)(A;;KA;;;BA)", wantErr: true},
		{name: "untrusted owner", sddl: "O:WDD:P(A;;KA;;;SY)(A;;KA;;;BA)", wantErr: true},
		{name: "low privilege preoccupied ACL", sddl: "O:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;BU)", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateWindowsJournalSecurityDescriptor(descriptor)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestWindowsRouteAddClassifiesExistingRoute(t *testing.T) {
	op := &windowsRouteOperator{
		interfaceLUID: 1,
		interfaceIdx:  2,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			create:    func(*windows.MibIpForwardRow2) error { return windows.ERROR_OBJECT_ALREADY_EXISTS },
		},
	}
	if _, err := op.Add(context.Background(), netip.MustParsePrefix("203.0.113.0/24")); !errors.Is(err, ErrRouteAlreadyExists) {
		t.Fatalf("error = %v, want ErrRouteAlreadyExists", err)
	}
}

func TestWindowsRouteAddReportsCommittedBeforePostCallCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	op := &windowsRouteOperator{
		interfaceLUID: 1,
		interfaceIdx:  2,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			create: func(*windows.MibIpForwardRow2) error {
				cancel()
				return nil
			},
		},
	}
	result, err := op.Add(ctx, netip.MustParsePrefix("203.0.113.0/24"))
	if !result.Committed || !errors.Is(err, context.Canceled) {
		t.Fatalf("Add result = %+v, error = %v; want committed cancellation", result, err)
	}
}

func TestWindowsRouteDeleteReportsCommittedBeforePostCallCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	op := &windowsRouteOperator{
		interfaceLUID: 1,
		interfaceIdx:  2,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get: func(*windows.MibIpForwardRow2) error {
				return nil
			},
			delete: func(*windows.MibIpForwardRow2) error {
				cancel()
				return nil
			},
		},
	}
	result, err := op.Delete(ctx, netip.MustParsePrefix("203.0.113.0/24"))
	if !result.Committed || !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete result = %+v, error = %v; want committed cancellation", result, err)
	}
}

func TestWindowsPrivateNamespaceRegistryLifecycle(t *testing.T) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := newWindowsRouteNamespaceSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("multiple instances close only the final reference", func(t *testing.T) {
		backend := &observedWindowsPrivateNamespaceBackend{}
		registry := backend.Registry()
		first, err := registry.Acquire("SharedAlias", "SharedBoundary", admins, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		second, err := registry.Acquire("SharedAlias", "SharedBoundary", admins, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if opens, closes := backend.Counts(); opens != 1 || closes != 0 {
			t.Fatalf("after two acquires opens=%d closes=%d, want 1 and 0", opens, closes)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		if opens, closes := backend.Counts(); opens != 1 || closes != 0 {
			t.Fatalf("after first close opens=%d closes=%d, want 1 and 0", opens, closes)
		}
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
		if err := second.Close(); err != nil {
			t.Fatalf("repeat reference close: %v", err)
		}
		if opens, closes := backend.Counts(); opens != 1 || closes != 1 {
			t.Fatalf("after final close opens=%d closes=%d, want 1 and 1", opens, closes)
		}
	})

	t.Run("concurrent instances share one registration", func(t *testing.T) {
		backend := &observedWindowsPrivateNamespaceBackend{}
		registry := backend.Registry()
		const instances = 32
		ready := make(chan error, instances)
		release := make(chan struct{})
		closed := make(chan error, instances)
		for range instances {
			go func() {
				reference, err := registry.Acquire("ConcurrentAlias", "ConcurrentBoundary", admins, descriptor)
				ready <- err
				if err != nil {
					closed <- nil
					return
				}
				<-release
				closed <- reference.Close()
			}()
		}
		for range instances {
			if err := <-ready; err != nil {
				t.Fatal(err)
			}
		}
		if opens, closes := backend.Counts(); opens != 1 || closes != 0 {
			t.Fatalf("while references live opens=%d closes=%d, want 1 and 0", opens, closes)
		}
		close(release)
		for range instances {
			if err := <-closed; err != nil {
				t.Fatal(err)
			}
		}
		if opens, closes := backend.Counts(); opens != 1 || closes != 1 {
			t.Fatalf("after concurrent closes opens=%d closes=%d, want 1 and 1", opens, closes)
		}
	})

	t.Run("last close permits a clean reopen", func(t *testing.T) {
		backend := &observedWindowsPrivateNamespaceBackend{}
		registry := backend.Registry()
		for range 2 {
			reference, err := registry.Acquire("ReopenAlias", "ReopenBoundary", admins, descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if err := reference.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if opens, closes := backend.Counts(); opens != 2 || closes != 2 {
			t.Fatalf("close/reopen opens=%d closes=%d, want 2 and 2", opens, closes)
		}
	})

	t.Run("different boundary identity or ACL fails closed", func(t *testing.T) {
		for _, test := range []struct {
			name         string
			boundaryName string
			boundarySID  *windows.SID
			security     *windows.SECURITY_DESCRIPTOR
		}{
			{name: "boundary name", boundaryName: "OtherBoundary", boundarySID: admins, security: descriptor},
			{name: "boundary SID", boundaryName: "TrustedBoundary", boundarySID: users, security: descriptor},
			{name: "ACL", boundaryName: "TrustedBoundary", boundarySID: admins, security: mustWindowsSecurityDescriptor(t, "D:P(A;;GA;;;BU)")},
		} {
			t.Run(test.name, func(t *testing.T) {
				backend := &observedWindowsPrivateNamespaceBackend{}
				registry := backend.Registry()
				reference, err := registry.Acquire("IdentityAlias", "TrustedBoundary", admins, descriptor)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := registry.Acquire("IdentityAlias", test.boundaryName, test.boundarySID, test.security); err == nil || !strings.Contains(err.Error(), "different boundary name, SID, or ACL") {
					t.Fatalf("identity conflict error = %v", err)
				}
				if err := reference.Close(); err != nil {
					t.Fatal(err)
				}
				if opens, closes := backend.Counts(); opens != 1 || closes != 1 {
					t.Fatalf("identity conflict opens=%d closes=%d, want 1 and 1", opens, closes)
				}
			})
		}
	})

	t.Run("empty canonical identity never enters registry", func(t *testing.T) {
		for _, test := range []struct {
			name         string
			wantError    string
			canonicalize func(string, string, *windows.SID, *windows.SECURITY_DESCRIPTOR) (windowsPrivateNamespaceIdentity, error)
		}{
			{
				name:      "identity error",
				wantError: "injected identity failure",
				canonicalize: func(string, string, *windows.SID, *windows.SECURITY_DESCRIPTOR) (windowsPrivateNamespaceIdentity, error) {
					return windowsPrivateNamespaceIdentity{}, errors.New("injected identity failure")
				},
			},
			{
				name:      "boundary SID",
				wantError: "boundary SID could not be canonicalized",
				canonicalize: func(alias, boundaryName string, sid *windows.SID, descriptor *windows.SECURITY_DESCRIPTOR) (windowsPrivateNamespaceIdentity, error) {
					return newWindowsPrivateNamespaceIdentityWithCanonicalizers(
						alias,
						boundaryName,
						sid,
						descriptor,
						func(*windows.SID) string { return "" },
						func(descriptor *windows.SECURITY_DESCRIPTOR) string { return descriptor.String() },
					)
				},
			},
			{
				name:      "descriptor",
				wantError: "security descriptor could not be canonicalized",
				canonicalize: func(alias, boundaryName string, sid *windows.SID, descriptor *windows.SECURITY_DESCRIPTOR) (windowsPrivateNamespaceIdentity, error) {
					return newWindowsPrivateNamespaceIdentityWithCanonicalizers(
						alias,
						boundaryName,
						sid,
						descriptor,
						func(sid *windows.SID) string { return sid.String() },
						func(*windows.SECURITY_DESCRIPTOR) string { return "" },
					)
				},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				backend := &observedWindowsPrivateNamespaceBackend{}
				registry := backend.Registry()
				registry.identity = test.canonicalize
				reference, err := registry.Acquire("EmptyIdentityAlias", "TrustedBoundary", admins, descriptor)
				if reference != nil || err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("empty identity reference=%v error=%v", reference, err)
				}
				if opens, closes := backend.Counts(); opens != 0 || closes != 0 {
					t.Fatalf("empty identity opens=%d closes=%d, want 0 and 0", opens, closes)
				}
				registry.mu.Lock()
				entries := len(registry.entries)
				registry.mu.Unlock()
				if entries != 0 {
					t.Fatalf("empty identity wrote %d registry entries", entries)
				}
			})
		}
	})

	t.Run("close failure poisons alias", func(t *testing.T) {
		closeErr := errors.New("injected namespace close failure")
		backend := &observedWindowsPrivateNamespaceBackend{closeErr: closeErr}
		registry := backend.Registry()
		reference, err := registry.Acquire("PoisonAlias", "PoisonBoundary", admins, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if err := reference.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("namespace close error = %v", err)
		}
		if err := reference.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("repeat namespace close error = %v", err)
		}
		if _, err := registry.Acquire("PoisonAlias", "PoisonBoundary", admins, descriptor); !errors.Is(err, closeErr) {
			t.Fatalf("acquire poisoned alias error = %v", err)
		}
		if opens, closes := backend.Counts(); opens != 1 || closes != 1 {
			t.Fatalf("poisoned alias opens=%d closes=%d, want 1 and 1", opens, closes)
		}
	})
}

func TestPrivateWindowsRouteJournalLockerReleasesNamespaceAfterPartialInit(t *testing.T) {
	backend := &observedWindowsPrivateNamespaceBackend{}
	locker := newPrivateWindowsRouteJournalLocker("PartialAlias", "PartialBoundary", "Mutex", time.Second)
	locker.registry = backend.Registry()
	locker.newMutex = func(name string, timeout time.Duration) *namedWindowsRouteJournalLocker {
		return &namedWindowsRouteJournalLocker{name: name, timeout: timeout, closed: true}
	}
	if err := locker.Open(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("partial mutex initialization error = %v", err)
	}
	if opens, closes := backend.Counts(); opens != 1 || closes != 1 {
		t.Fatalf("partial initialization opens=%d closes=%d, want 1 and 1", opens, closes)
	}
	if err := locker.Close(); err != nil {
		t.Fatal(err)
	}
}

func windowsRouteRowKey(row windows.MibIpForwardRow2) string {
	return fmt.Sprintf("%d:%d:%d:%x", row.InterfaceLuid, row.InterfaceIndex,
		row.DestinationPrefix.PrefixLength, row.DestinationPrefix.Prefix.Data)
}

func testWindowsRouteJournalEntry(t *testing.T, op *windowsRouteOperator, prefix netip.Prefix, state string) windowsRouteJournalEntry {
	t.Helper()
	txnID, err := newWindowsRouteTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	return newWindowsRouteJournalEntry(op, prefix, txnID, state)
}

type observedLocalWindowsRouteJournalLocker struct {
	mu   sync.Mutex
	held bool
}

type observedWindowsPrivateNamespaceBackend struct {
	mu       sync.Mutex
	opens    int
	closes   int
	openErr  error
	closeErr error
}

func (b *observedWindowsPrivateNamespaceBackend) Registry() *windowsPrivateNamespaceRegistry {
	return newWindowsPrivateNamespaceRegistry(
		func(string, string, *windows.SID, *windows.SECURITY_DESCRIPTOR) (*windowsPrivateNamespace, error) {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.opens++
			if b.openErr != nil {
				return nil, b.openErr
			}
			return &windowsPrivateNamespace{}, nil
		},
		func(*windowsPrivateNamespace) error {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.closes++
			return b.closeErr
		},
	)
}

func (b *observedWindowsPrivateNamespaceBackend) Counts() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.opens, b.closes
}

func mustWindowsSecurityDescriptor(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func (l *observedLocalWindowsRouteJournalLocker) Lock() (*windowsRouteJournalLock, error) {
	l.mu.Lock()
	l.held = true
	return &windowsRouteJournalLock{unlock: func() error {
		l.held = false
		l.mu.Unlock()
		return nil
	}}, nil
}
