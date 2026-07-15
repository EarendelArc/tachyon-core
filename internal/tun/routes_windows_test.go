//go:build windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/windows"
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

	journal := newWindowsRouteJournal(filepath.Join(t.TempDir(), "routes.json"))
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{
			{InterfaceLUID: 55, InterfaceIndex: 12, Destination: prefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRouteActive},
			{InterfaceLUID: 99, InterfaceIndex: 12, Destination: otherPrefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRouteActive},
		},
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

func TestWindowsRouteJournalRefusesChangedUserRoute(t *testing.T) {
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
	journal := newWindowsRouteJournal(filepath.Join(t.TempDir(), "routes.json"))
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{{
			InterfaceLUID: 55, InterfaceIndex: 12, Destination: prefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRouteActive,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err == nil {
		t.Fatal("expected changed journal route to block reconcile")
	}
}

func TestWindowsRouteJournalPreservesAmbiguousPendingRoute(t *testing.T) {
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
	op.api.delete = func(*windows.MibIpForwardRow2) error {
		t.Fatal("pending route must not be deleted automatically")
		return nil
	}
	journal := newWindowsRouteJournal(filepath.Join(t.TempDir(), "routes.json"))
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{{
			InterfaceLUID: 55, InterfaceIndex: 12, Destination: prefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRoutePending,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err == nil {
		t.Fatal("ambiguous pending route should block startup reconcile")
	}
	data, err := journal.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 1 || data.Entries[0].State != windowsRoutePending {
		t.Fatalf("pending audit entry was not preserved: %+v", data.Entries)
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
	if err := op.Add(context.Background(), netip.MustParsePrefix("203.0.113.0/24")); !errors.Is(err, ErrRouteAlreadyExists) {
		t.Fatalf("error = %v, want ErrRouteAlreadyExists", err)
	}
}

func windowsRouteRowKey(row windows.MibIpForwardRow2) string {
	return fmt.Sprintf("%d:%d:%d:%x", row.InterfaceLuid, row.InterfaceIndex,
		row.DestinationPrefix.PrefixLength, row.DestinationPrefix.Prefix.Data)
}
