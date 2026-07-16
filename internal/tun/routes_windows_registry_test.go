//go:build windows && routejournalintegration

package tun

import (
	"errors"
	"fmt"
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

	want := []byte(`{"version":3,"entries":[]}`)
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

func TestWindowsRouteJournalMachineMutexMultiProcess(t *testing.T) {
	keyPath := uniqueWindowsRouteJournalTestKey("MultiProcess")
	mutexName := uniqueWindowsRouteJournalTestMutex("MultiProcess")
	storage := &registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State"}
	cleanupWindowsRouteJournalTestKey(t, keyPath)
	t.Cleanup(func() { cleanupWindowsRouteJournalTestKey(t, keyPath) })
	journal := &windowsRouteJournal{storage: storage, locker: &namedWindowsRouteJournalLocker{name: mutexName, timeout: windowsRouteLockTimeout}}
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
				"TACHYON_ROUTE_JOURNAL_TEST_MUTEX="+mutexName,
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
}

func TestWindowsRouteJournalMachineMutexTimeoutAndAbandonment(t *testing.T) {
	mutexName := uniqueWindowsRouteJournalTestMutex("Wait")
	locker := &namedWindowsRouteJournalLocker{name: mutexName, timeout: 2 * time.Second}
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

	persistentHandle := openWindowsRouteJournalTestMutex(t, mutexName)
	defer windows.CloseHandle(persistentHandle)
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsRouteJournalProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), windowsRouteJournalHelperEnv+"=abandon", "TACHYON_ROUTE_JOURNAL_TEST_MUTEX="+mutexName)
	if wire, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("abandon helper: %v\n%s", err, wire)
	}
	lock, err := locker.Lock()
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
	mutexName := os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_MUTEX")
	locker := &namedWindowsRouteJournalLocker{name: mutexName, timeout: windowsRouteLockTimeout}
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
	storage := &registryWindowsRouteJournalStorage{
		root: registry.LOCAL_MACHINE, keyPath: os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_KEY"), valueName: "State",
	}
	journal := &windowsRouteJournal{storage: storage, locker: locker}
	data, err := journal.load()
	if err == nil {
		time.Sleep(75 * time.Millisecond)
		data.Entries = append(data.Entries, windowsRouteJournalEntry{
			InterfaceLUID: uint64(marker), InterfaceIndex: uint32(marker), Destination: fmt.Sprintf("192.0.2.%d/32", marker),
			Metric: uint32(marker), Protocol: windowsRouteProtocol, BaselineAbsent: true, State: windowsRouteActive,
		})
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
