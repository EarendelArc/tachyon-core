//go:build windows && routeintegration

package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const windowsRealRouteHelperEnv = "TACHYON_REAL_ROUTE_TEST_HELPER"

func TestWindowsRouteJournalAbandonedPendingRealChildRecovery(t *testing.T) {
	if os.Getenv("TACHYON_ALLOW_REAL_ROUTE_TEST") != "1" {
		t.Fatal("real route integration is fail-closed; set TACHYON_ALLOW_REAL_ROUTE_TEST=1 on an isolated elevated CI runner")
	}

	keyPath := uniqueRealRouteTestKey()
	storage := &registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State"}
	cleanupRealRouteTestKey(t, keyPath)
	t.Cleanup(func() { cleanupRealRouteTestKey(t, keyPath) })
	if err := (&windowsRouteJournal{storage: storage}).save(windowsRouteJournalData{Version: windowsRouteJournalVersion}); err != nil {
		t.Fatalf("initialize protected real-route journal: %v", err)
	}

	interfaceLUID, interfaceIndex, err := realRouteTestInterface()
	if err != nil {
		t.Fatal(err)
	}
	op := &windowsRouteOperator{
		interfaceLUID: interfaceLUID,
		interfaceIdx:  interfaceIndex,
		api:           systemWindowsRouteAPI(),
		adapterOwned:  func() bool { return true },
	}
	prefix, err := unusedRealRouteTestPrefix(op)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = op.Delete(ctx, prefix)
	})

	mutexName, err := storage.machineMutexName()
	if err != nil {
		t.Fatal(err)
	}
	persistentHandle := openRealRouteTestMutex(t, mutexName)
	defer windows.CloseHandle(persistentHandle)

	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsRouteJournalRealRouteProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		windowsRealRouteHelperEnv+"=create-pending-and-abandon",
		"TACHYON_REAL_ROUTE_TEST_KEY="+keyPath,
		"TACHYON_REAL_ROUTE_TEST_LUID="+strconv.FormatUint(interfaceLUID, 10),
		"TACHYON_REAL_ROUTE_TEST_INDEX="+strconv.FormatUint(uint64(interfaceIndex), 10),
		"TACHYON_REAL_ROUTE_TEST_PREFIX="+prefix.String(),
	)
	if wire, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pending route child: %v\n%s", err, wire)
	}

	observed := &observingWindowsRouteJournalLocker{inner: &protectedWindowsRouteJournalLocker{storage: storage, timeout: windowsRouteLockTimeout}}
	journal := &windowsRouteJournal{storage: storage, locker: observed}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("close real-route journal: %v", err)
		}
	})
	op.journal = journal
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatalf("recover abandoned pending real route: %v", err)
	}
	if !observed.abandoned {
		t.Fatal("pending child recovery did not observe an abandoned machine mutex")
	}
	state, err := op.Read(context.Background(), prefix)
	if err != nil || state.Exists {
		t.Fatalf("real route remains after recovery: state=%+v error=%v", state, err)
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 0 {
		t.Fatalf("journal remains after real route recovery: data=%+v error=%v", data, err)
	}
}

func TestWindowsRouteJournalRecordFailureRealRouteRollback(t *testing.T) {
	if os.Getenv("TACHYON_ALLOW_REAL_ROUTE_TEST") != "1" {
		t.Fatal("real route integration is fail-closed; set TACHYON_ALLOW_REAL_ROUTE_TEST=1 on an isolated elevated CI runner")
	}

	keyPath := uniqueRealRouteTestKey()
	baseStorage := &registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State"}
	cleanupRealRouteTestKey(t, keyPath)
	t.Cleanup(func() { cleanupRealRouteTestKey(t, keyPath) })
	if err := (&windowsRouteJournal{storage: baseStorage}).save(windowsRouteJournalData{Version: windowsRouteJournalVersion}); err != nil {
		t.Fatalf("initialize protected real-route journal: %v", err)
	}

	interfaceLUID, interfaceIndex, err := realRouteTestInterface()
	if err != nil {
		t.Fatal(err)
	}
	storage := &failNthWindowsRouteJournalStorage{
		windowsRouteJournalStorage: baseStorage,
		failAt:                     2,
		err:                        errors.New("injected real active persistence failure"),
	}
	locker := &protectedWindowsRouteJournalLocker{storage: baseStorage, timeout: windowsRouteLockTimeout}
	if err := locker.Open(); err != nil {
		t.Fatal(err)
	}
	journal := &windowsRouteJournal{storage: storage, locker: locker}
	op := &windowsRouteOperator{
		interfaceLUID: interfaceLUID,
		interfaceIdx:  interfaceIndex,
		api:           systemWindowsRouteAPI(),
		journal:       journal,
		adapterOwned:  func() bool { return true },
	}
	prefix, err := unusedRealRouteTestPrefix(op)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = op.Delete(ctx, prefix)
		_ = journal.Close()
	})

	if _, err := installRouteTransaction(context.Background(), op, []netip.Prefix{prefix}); err == nil || !strings.Contains(err.Error(), "injected real active persistence failure") {
		t.Fatalf("real route install error = %v", err)
	}
	state, err := op.Read(context.Background(), prefix)
	if err != nil || state.Exists {
		t.Fatalf("real route remains after failed active persistence: state=%+v error=%v", state, err)
	}
	data, err := journal.load()
	if err != nil || len(data.Entries) != 0 {
		t.Fatalf("journal remains after failed active persistence: data=%+v error=%v", data, err)
	}
}

func TestWindowsRouteJournalRealRouteProcessHelper(t *testing.T) {
	if os.Getenv(windowsRealRouteHelperEnv) == "" {
		return
	}
	luid, err := strconv.ParseUint(os.Getenv("TACHYON_REAL_ROUTE_TEST_LUID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	index, err := strconv.ParseUint(os.Getenv("TACHYON_REAL_ROUTE_TEST_INDEX"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := netip.ParsePrefix(os.Getenv("TACHYON_REAL_ROUTE_TEST_PREFIX"))
	if err != nil {
		t.Fatal(err)
	}
	storage := &registryWindowsRouteJournalStorage{
		root: registry.LOCAL_MACHINE, keyPath: os.Getenv("TACHYON_REAL_ROUTE_TEST_KEY"), valueName: "State",
	}
	journal := &windowsRouteJournal{storage: storage, locker: &protectedWindowsRouteJournalLocker{storage: storage, timeout: windowsRouteLockTimeout}}
	op := &windowsRouteOperator{
		interfaceLUID: luid,
		interfaceIdx:  uint32(index),
		api:           systemWindowsRouteAPI(),
		journal:       journal,
		adapterOwned:  func() bool { return true },
	}
	if err := journal.prepare(context.Background(), op, prefix); err != nil {
		t.Fatal(err)
	}
	result, err := op.Add(context.Background(), prefix)
	if err != nil || !result.Committed {
		t.Fatalf("create real pending route: result=%+v error=%v", result, err)
	}
	os.Exit(0)
}

type observingWindowsRouteJournalLocker struct {
	inner     windowsRouteJournalLocker
	abandoned bool
}

func (l *observingWindowsRouteJournalLocker) Open() error {
	if lifecycle, ok := l.inner.(windowsRouteJournalLockerLifecycle); ok {
		return lifecycle.Open()
	}
	return nil
}

func (l *observingWindowsRouteJournalLocker) Close() error {
	if lifecycle, ok := l.inner.(windowsRouteJournalLockerLifecycle); ok {
		return lifecycle.Close()
	}
	return nil
}

type failNthWindowsRouteJournalStorage struct {
	windowsRouteJournalStorage
	writes int
	failAt int
	err    error
}

func (s *failNthWindowsRouteJournalStorage) Write(wire []byte) error {
	s.writes++
	if s.writes == s.failAt {
		return s.err
	}
	return s.windowsRouteJournalStorage.Write(wire)
}

func (l *observingWindowsRouteJournalLocker) Lock() (*windowsRouteJournalLock, error) {
	lock, err := l.inner.Lock()
	if err == nil {
		l.abandoned = lock.abandoned
	}
	return lock, err
}

func realRouteTestInterface() (uint64, uint32, error) {
	var index uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &index); err != nil {
		return 0, 0, fmt.Errorf("resolve real-route test interface: %w", err)
	}
	row := windows.MibIfRow2{InterfaceIndex: index}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
		return 0, 0, fmt.Errorf("resolve real-route test interface LUID: %w", err)
	}
	if row.InterfaceLuid == 0 || row.InterfaceIndex == 0 {
		return 0, 0, errors.New("real-route test interface has no stable LUID/index")
	}
	return row.InterfaceLuid, row.InterfaceIndex, nil
}

func unusedRealRouteTestPrefix(op *windowsRouteOperator) (netip.Prefix, error) {
	start := int(windows.GetCurrentProcessId()%200) + 1
	for offset := range 50 {
		octet := (start+offset-1)%254 + 1
		prefix := netip.MustParsePrefix(fmt.Sprintf("192.0.2.%d/32", octet))
		state, err := op.Read(context.Background(), prefix)
		if err != nil {
			return netip.Prefix{}, err
		}
		if !state.Exists {
			return prefix, nil
		}
	}
	return netip.Prefix{}, errors.New("no unused TEST-NET-1 host route was available")
}

func openRealRouteTestMutex(t *testing.T, mutexName string) windows.Handle {
	t.Helper()
	descriptor, err := newWindowsRouteMutexSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		t.Fatal(err)
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := windows.CreateMutex(&security, false, name)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(security)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		t.Fatal(err)
	}
	if err := validateWindowsRouteMutex(handle); err != nil {
		windows.CloseHandle(handle)
		t.Fatal(err)
	}
	return handle
}

func uniqueRealRouteTestKey() string {
	return fmt.Sprintf(`SOFTWARE\TachyonRouteRealTest-%d-%d`, windows.GetCurrentProcessId(), time.Now().UnixNano())
}

func cleanupRealRouteTestKey(t *testing.T, keyPath string) {
	t.Helper()
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.ALL_ACCESS|registry.WOW64_64KEY); err == nil {
		_ = registry.DeleteKey(key, windowsRouteCoordinationKey)
		key.Close()
	}
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return
	}
	if err != nil {
		t.Errorf("open HKLM test parent: %v", err)
		return
	}
	defer parent.Close()
	leaf := keyPath[len(`SOFTWARE\`):]
	if err := registry.DeleteKey(parent, leaf); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Errorf("delete real-route test key: %v", err)
	}
}
