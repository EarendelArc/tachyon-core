//go:build windows && routejournalintegration

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
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const windowsRouteJournalHelperEnv = "TACHYON_ROUTE_JOURNAL_TEST_HELPER"

func TestWindowsRouteJournalRegistryIntegration(t *testing.T) {
	keyPath := uniqueWindowsRouteJournalTestKey("Registry")
	storage := registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State"}
	cleanupWindowsRouteJournalTestKey(t, keyPath)
	t.Cleanup(func() { cleanupWindowsRouteJournalTestKey(t, keyPath) })

	want := []byte(`{"version":4,"entries":[]}`)
	if err := storage.Write(want); err != nil {
		t.Fatalf("write protected HKLM journal (Windows CI must run elevated): %v", err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatalf("open journal through explicit 64-bit registry view: %v", err)
	}
	if err := validateWindowsRouteJournalRegistryKey(key); err != nil {
		key.Close()
		t.Fatalf("real journal key ACL: %v", err)
	}
	key.Close()
	got, err := storage.Read()
	if err != nil || string(got) != string(want) {
		t.Fatalf("read real REG_BINARY journal = %q, error=%v", got, err)
	}

	key, err = registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.SetStringValue(storage.valueName, "wrong type"); err != nil {
		key.Close()
		t.Fatal(err)
	}
	key.Close()
	if _, err := storage.Read(); err == nil || !strings.Contains(err.Error(), "REG_BINARY") {
		t.Fatalf("wrong registry type error = %v", err)
	}

	key, err = registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.SetBinaryValue(storage.valueName, make([]byte, windowsRouteJournalMaxSize+1)); err != nil {
		key.Close()
		t.Fatal(err)
	}
	key.Close()
	if _, err := storage.Read(); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("oversized registry value error = %v", err)
	}

	boundary := make([]byte, windowsRouteJournalMaxSize)
	if err := storage.Write(boundary); err != nil {
		t.Fatalf("write exact 1 MiB boundary: %v", err)
	}
	if got, err := storage.Read(); err != nil || len(got) != windowsRouteJournalMaxSize {
		t.Fatalf("read exact 1 MiB boundary length=%d error=%v", len(got), err)
	}

	untrustedPath := uniqueWindowsRouteJournalTestKey("Untrusted")
	cleanupWindowsRouteJournalTestKey(t, untrustedPath)
	t.Cleanup(func() { cleanupWindowsRouteJournalTestKey(t, untrustedPath) })
	untrusted, _, err := registry.CreateKey(registry.LOCAL_MACHINE, untrustedPath, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil {
		t.Fatalf("create inherited-ACL HKLM test key: %v", err)
	}
	if err := untrusted.SetBinaryValue("State", want); err != nil {
		untrusted.Close()
		t.Fatal(err)
	}
	untrusted.Close()
	untrustedStorage := registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: untrustedPath, valueName: "State"}
	if _, err := untrustedStorage.Read(); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("inherited/untrusted ACL was not rejected: %v", err)
	}
}

func TestWindowsRouteJournalInitializesSecretFromProtectedEmptyHKLMKey(t *testing.T) {
	keyPath := uniqueWindowsRouteJournalTestKey("Empty")
	cleanupWindowsRouteJournalTestKey(t, keyPath)
	t.Cleanup(func() { cleanupWindowsRouteJournalTestKey(t, keyPath) })
	key, _, err := createWindowsRouteJournalRegistryKey(registry.LOCAL_MACHINE, keyPath, "")
	if err != nil {
		t.Fatalf("create protected empty HKLM key: %v", err)
	}
	key.Close()

	storage := &registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State"}
	first, err := storage.machineMutexName()
	if err != nil {
		t.Fatal(err)
	}
	second, err := storage.machineMutexName()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, windowsRouteJournalMutexPrefix) {
		t.Fatalf("derived mutex names first=%q second=%q", first, second)
	}
	if wire, err := storage.Read(); err != nil || len(wire) != 0 {
		t.Fatalf("empty journal read=%q error=%v", wire, err)
	}
}

func TestWindowsRouteJournalMachineMutexMultiProcess(t *testing.T) {
	keyPath := uniqueWindowsRouteJournalTestKey("MultiProcess")
	storage := &registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State"}
	cleanupWindowsRouteJournalTestKey(t, keyPath)
	t.Cleanup(func() { cleanupWindowsRouteJournalTestKey(t, keyPath) })
	journal := &windowsRouteJournal{storage: storage, locker: &protectedWindowsRouteJournalLocker{storage: storage, timeout: windowsRouteLockTimeout}}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("close multiprocess journal: %v", err)
		}
	})
	if err := journal.save(windowsRouteJournalData{Version: windowsRouteJournalVersion}); err != nil {
		t.Fatalf("initialize multiprocess HKLM journal: %v", err)
	}

	const processCount = 8
	type result struct {
		marker int
		wire   []byte
		err    error
	}
	results := make(chan result, processCount)
	for marker := 1; marker <= processCount; marker++ {
		go func() {
			cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsRouteJournalProcessHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(),
				windowsRouteJournalHelperEnv+"=append",
				"TACHYON_ROUTE_JOURNAL_TEST_KEY="+keyPath,
				"TACHYON_ROUTE_JOURNAL_TEST_MARKER="+strconv.Itoa(marker),
			)
			wire, err := cmd.CombinedOutput()
			results <- result{marker: marker, wire: wire, err: err}
		}()
	}
	for range processCount {
		result := <-results
		if result.err != nil {
			t.Fatalf("journal helper %d: %v\n%s", result.marker, result.err, result.wire)
		}
	}

	lock, err := journal.locker.Lock()
	if err != nil {
		t.Fatal(err)
	}
	data, loadErr := journal.load()
	unlockErr := lock.unlock()
	if err := errors.Join(loadErr, unlockErr); err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint64]bool, processCount)
	for _, entry := range data.Entries {
		seen[entry.InterfaceLUID] = true
	}
	if len(data.Entries) != processCount || len(seen) != processCount {
		t.Fatalf("multiprocess journal entries=%+v, want %d unique entries", data.Entries, processCount)
	}

	conflictPrefix := netip.MustParsePrefix("198.51.100.0/24")
	owner := &windowsRouteOperator{interfaceLUID: 1000, interfaceIdx: 1000}
	txnID, err := newWindowsRouteTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	lock, err = journal.locker.Lock()
	if err != nil {
		t.Fatal(err)
	}
	data, err = journal.load()
	if err == nil {
		data.Entries = append(data.Entries, newWindowsRouteJournalEntry(owner, conflictPrefix, txnID, windowsRouteActive))
		err = journal.save(data)
	}
	err = errors.Join(err, lock.unlock())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsRouteJournalProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		windowsRouteJournalHelperEnv+"=claim-conflict",
		"TACHYON_ROUTE_JOURNAL_TEST_KEY="+keyPath,
		"TACHYON_ROUTE_JOURNAL_TEST_MARKER=1001",
		"TACHYON_ROUTE_JOURNAL_TEST_PREFIX="+conflictPrefix.String(),
	)
	if wire, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("different-LUID conflict helper: %v\n%s", err, wire)
	}
}

func TestWindowsRouteJournalMachineMutexTimeoutAndAbandonment(t *testing.T) {
	mutexName := uniqueWindowsRouteJournalTestMutex("Wait")
	locker := &namedWindowsRouteJournalLocker{name: mutexName, timeout: 2 * time.Second}
	t.Cleanup(func() {
		if err := locker.Close(); err != nil {
			t.Errorf("close persistent machine mutex: %v", err)
		}
	})
	held := make(chan *windowsRouteJournalLock, 1)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		lock, err := locker.Lock()
		if err != nil {
			done <- err
			return
		}
		held <- lock
		<-release
		done <- lock.unlock()
	}()
	select {
	case <-held:
	case err := <-done:
		t.Fatalf("acquire first machine mutex (Windows CI must run elevated): %v", err)
	}
	_, err := (&namedWindowsRouteJournalLocker{name: mutexName, timeout: 100 * time.Millisecond}).Lock()
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("contended machine mutex error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	keeper := locker.handle
	if keeper == 0 {
		t.Fatal("machine mutex keeper handle was destroyed after transition unlock")
	}
	if err := validateWindowsRouteMutex(keeper); err != nil {
		t.Fatalf("persistent machine mutex keeper is no longer trusted: %v", err)
	}
	lock, err := locker.Lock()
	if err != nil {
		t.Fatalf("reacquire persistent machine mutex: %v", err)
	}
	if locker.handle != keeper {
		lock.unlock()
		t.Fatal("machine mutex was recreated between transitions")
	}
	if err := lock.unlock(); err != nil {
		t.Fatal(err)
	}

	persistentHandle := openWindowsRouteJournalTestMutex(t, mutexName)
	defer windows.CloseHandle(persistentHandle)
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsRouteJournalProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), windowsRouteJournalHelperEnv+"=abandon", "TACHYON_ROUTE_JOURNAL_TEST_MUTEX="+mutexName)
	if wire, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("abandon helper: %v\n%s", err, wire)
	}
	lock, err = locker.Lock()
	if err != nil {
		t.Fatalf("acquire abandoned machine mutex: %v", err)
	}
	if !lock.abandoned {
		lock.unlock()
		t.Fatal("abandoned machine mutex was not reported")
	}
	if err := lock.unlock(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsRouteJournalProcessHelper(t *testing.T) {
	action := os.Getenv(windowsRouteJournalHelperEnv)
	if action == "" {
		return
	}
	keyPath := os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_KEY")
	storage := &registryWindowsRouteJournalStorage{
		root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State",
	}
	var locker windowsRouteJournalLocker = &protectedWindowsRouteJournalLocker{storage: storage, timeout: windowsRouteLockTimeout}
	if mutexName := os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_MUTEX"); mutexName != "" {
		locker = &namedWindowsRouteJournalLocker{name: mutexName, timeout: windowsRouteLockTimeout}
	}
	journal := &windowsRouteJournal{storage: storage, locker: locker}
	if action == "claim-conflict" {
		marker, err := strconv.Atoi(os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_MARKER"))
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := netip.ParsePrefix(os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_PREFIX"))
		if err != nil {
			t.Fatal(err)
		}
		op := &windowsRouteOperator{
			interfaceLUID: uint64(marker),
			interfaceIdx:  uint32(marker),
			api: windowsRouteAPI{
				initEntry: func(*windows.MibIpForwardRow2) {},
				get:       func(*windows.MibIpForwardRow2) error { return windows.ERROR_NOT_FOUND },
			},
		}
		if err := journal.prepare(context.Background(), op, prefix); err == nil || !strings.Contains(err.Error(), "already owned") {
			t.Fatalf("different-LUID destination claim error = %v", err)
		}
		return
	}
	lock, err := locker.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if action == "abandon" {
		os.Exit(0)
	}
	if action != "append" {
		lock.unlock()
		t.Fatalf("unknown helper action %q", action)
	}
	marker, err := strconv.Atoi(os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_MARKER"))
	if err != nil {
		lock.unlock()
		t.Fatal(err)
	}
	data, err := journal.load()
	if err == nil {
		time.Sleep(75 * time.Millisecond)
		op := &windowsRouteOperator{interfaceLUID: uint64(marker), interfaceIdx: uint32(marker)}
		txnID, txnErr := newWindowsRouteTransactionID()
		if txnErr != nil {
			err = txnErr
		} else {
			prefix := netip.MustParsePrefix(fmt.Sprintf("192.0.2.%d/32", marker))
			data.Entries = append(data.Entries, newWindowsRouteJournalEntry(op, prefix, txnID, windowsRouteActive))
		}
		err = journal.save(data)
	}
	err = errors.Join(err, lock.unlock())
	if err != nil {
		t.Fatal(err)
	}
}

func uniqueWindowsRouteJournalTestKey(label string) string {
	return fmt.Sprintf(`SOFTWARE\TachyonRouteJournalTest-%s-%d-%d`, label, windows.GetCurrentProcessId(), time.Now().UnixNano())
}

func uniqueWindowsRouteJournalTestMutex(label string) string {
	return fmt.Sprintf(`Global\Tachyon.RouteJournal.Test.%s.%d.%d`, label, windows.GetCurrentProcessId(), time.Now().UnixNano())
}

func cleanupWindowsRouteJournalTestKey(t *testing.T, keyPath string) {
	t.Helper()
	parts := strings.Split(keyPath, `\`)
	if key, openErr := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.ALL_ACCESS|registry.WOW64_64KEY); openErr == nil {
		_ = registry.DeleteKey(key, windowsRouteCoordinationKey)
		key.Close()
	}
	parentPath := strings.Join(parts[:len(parts)-1], `\`)
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, parentPath, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return
	}
	if err != nil {
		t.Errorf("open 64-bit registry test parent for cleanup: %v", err)
		return
	}
	defer parent.Close()
	if err := registry.DeleteKey(parent, parts[len(parts)-1]); err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		t.Errorf("delete 64-bit registry test key %q: %v", keyPath, err)
	}
}

func openWindowsRouteJournalTestMutex(t *testing.T, mutexName string) windows.Handle {
	t.Helper()
	descriptor, err := newWindowsRouteMutexSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		t.Fatal(err)
	}
	security := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateMutex(&security, false, name)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(security)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		t.Fatalf("create persistent test mutex: %v", err)
	}
	if err := validateWindowsRouteMutex(handle); err != nil {
		windows.CloseHandle(handle)
		t.Fatalf("validate persistent test mutex: %v", err)
	}
	return handle
}
