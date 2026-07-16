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
	"testing"

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
		Entries: []windowsRouteJournalEntry{{
			InterfaceLUID: 55, InterfaceIndex: 12, Destination: prefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRouteActive,
		}},
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

func TestWindowsRouteJournalDropsAmbiguousPendingRoute(t *testing.T) {
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
	journal := newWindowsRouteJournalForTest()
	op.journal = journal
	if err := journal.save(windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{{
			InterfaceLUID: 55, InterfaceIndex: 12, Destination: prefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRoutePending,
		}},
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
		t.Fatalf("pending non-ownership entry was preserved: %+v", data.Entries)
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
		Entries: []windowsRouteJournalEntry{{
			InterfaceLUID: 55, InterfaceIndex: 12, Destination: prefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRouteActive,
		}},
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
		Entries: []windowsRouteJournalEntry{{
			InterfaceLUID: 55, InterfaceIndex: 12, Destination: prefix.String(), Metric: windowsRouteMetric, Protocol: windowsRouteProtocol, State: windowsRouteDeleting,
		}},
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

func TestDefaultWindowsRouteJournalUsesFixedMachineRegistryKey(t *testing.T) {
	t.Setenv("TACHYON_ROUTE_JOURNAL", filepath.Join(t.TempDir(), "forged.json"))
	journal, err := newDefaultWindowsRouteJournal()
	if err != nil {
		t.Fatal(err)
	}
	storage, ok := journal.storage.(*registryWindowsRouteJournalStorage)
	if !ok {
		t.Fatalf("default storage = %T, want registry storage", journal.storage)
	}
	if storage.root != registry.LOCAL_MACHINE || storage.keyPath != windowsRouteJournalKey || storage.valueName != windowsRouteJournalValue {
		t.Fatalf("registry location = root %v path %q value %q", storage.root, storage.keyPath, storage.valueName)
	}
}

func TestWindowsRouteJournalWritesWholeAtomicStatesAndCleansUp(t *testing.T) {
	journal := newWindowsRouteJournalForTest()
	storage := journal.storage.(*memoryWindowsRouteJournalStorage)
	op := &windowsRouteOperator{interfaceLUID: 55, interfaceIdx: 12, journal: journal}
	prefix := netip.MustParsePrefix("203.0.113.0/24")

	if err := journal.prepare(op, prefix); err != nil {
		t.Fatal(err)
	}
	if err := journal.record(op, prefix); err != nil {
		t.Fatal(err)
	}
	if err := journal.prepareDeletion(op, prefix); err != nil {
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
	}
	if err := journal.release(op, prefix); err != nil {
		t.Fatal(err)
	}
	if storage.value != nil || storage.clearCalls != 1 {
		t.Fatalf("empty journal cleanup left value=%q clearCalls=%d", storage.value, storage.clearCalls)
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

	tests := []struct {
		name    string
		sddl    string
		wantErr bool
	}{
		{name: "protected system and admins", sddl: "O:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)"},
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

func windowsRouteRowKey(row windows.MibIpForwardRow2) string {
	return fmt.Sprintf("%d:%d:%d:%x", row.InterfaceLuid, row.InterfaceIndex,
		row.DestinationPrefix.PrefixLength, row.DestinationPrefix.Prefix.Data)
}
