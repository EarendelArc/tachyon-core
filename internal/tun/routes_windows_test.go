//go:build windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type recordingWindowsJournalSecurity struct {
	testWindowsRouteJournalSecurity
	protected []string
	validated []string
}

func (s *recordingWindowsJournalSecurity) Protect(path string) error {
	s.protected = append(s.protected, path)
	return nil
}

func (s *recordingWindowsJournalSecurity) Validate(path string) error {
	s.validated = append(s.validated, path)
	return nil
}

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

	journal := newWindowsRouteJournalForTest(filepath.Join(t.TempDir(), "routes.json"))
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
	journal := newWindowsRouteJournalForTest(filepath.Join(t.TempDir(), "routes.json"))
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
	journal := newWindowsRouteJournalForTest(filepath.Join(t.TempDir(), "routes.json"))
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
	journal := newWindowsRouteJournalForTest(filepath.Join(t.TempDir(), "routes.json"))
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

func TestWindowsRouteJournalCorruptionCannotDriveDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	journal := newWindowsRouteJournalForTest(path)
	if err := journal.security.Prepare(journal.root, journal.path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"entries":[`), 0o600); err != nil {
		t.Fatal(err)
	}
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

func TestWindowsRouteJournalPathRejectsEscape(t *testing.T) {
	root := filepath.Join(t.TempDir(), "protected")
	if err := validateWindowsJournalPath(root, filepath.Join(root, "routes.json")); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsJournalPath(root, filepath.Join(root, "..", "forged.json")); err == nil {
		t.Fatal("journal path outside protected root was accepted")
	}
}

func TestDefaultWindowsRouteJournalUsesMachineProgramData(t *testing.T) {
	t.Setenv("TACHYON_ROUTE_JOURNAL", filepath.Join(t.TempDir(), "forged.json"))
	journal, err := newDefaultWindowsRouteJournal()
	if err != nil {
		t.Fatal(err)
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := filepath.Join(programData, "Tachyon")
	if !strings.EqualFold(journal.root, wantRoot) || filepath.Dir(journal.path) != journal.root {
		t.Fatalf("journal root/path = %q / %q, want protected ProgramData root %q", journal.root, journal.path, wantRoot)
	}
}

func TestWindowsRouteJournalReprotectsEveryAtomicReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	security := &recordingWindowsJournalSecurity{}
	journal := &windowsRouteJournal{root: filepath.Dir(path), path: path, security: security}
	data := windowsRouteJournalData{
		Version: windowsRouteJournalVersion,
		Entries: []windowsRouteJournalEntry{{Destination: "203.0.113.0/24", State: windowsRoutePending}},
	}
	for range 2 {
		if err := journal.save(data); err != nil {
			t.Fatal(err)
		}
	}
	destinationProtects := 0
	for _, protected := range security.protected {
		if protected == path {
			destinationProtects++
		}
	}
	if destinationProtects != 2 || len(security.validated) != 2 {
		t.Fatalf("destination protects=%d validates=%d, want one of each per replace", destinationProtects, len(security.validated))
	}
}

func TestWindowsRouteJournalRejectsReparseAttributes(t *testing.T) {
	if err := validateWindowsJournalAttributes(`C:\ProgramData\Tachyon`, windows.FILE_ATTRIBUTE_DIRECTORY); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsJournalAttributes(`C:\ProgramData\Tachyon`, windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT); err == nil {
		t.Fatal("reparse point attributes were accepted")
	}
}

func TestWindowsRouteJournalSecurityDescriptorRequiresProtectedTrustedACL(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		wantErr bool
	}{
		{name: "protected system and admins", sddl: "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"},
		{name: "inheritance enabled", sddl: "O:SYD:(A;;GA;;;SY)(A;;GA;;;BA)", wantErr: true},
		{name: "untrusted owner", sddl: "O:WDD:P(A;;GA;;;SY)(A;;GA;;;BA)", wantErr: true},
		{name: "untrusted writer", sddl: "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)", wantErr: true},
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
