//go:build windows && routejournalintegration

package tun

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

var procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")

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

// The name is retained because release CI selects this integration test explicitly.
func TestWindowsRouteJournalInitializesSecretFromProtectedEmptyHKLMKey(t *testing.T) {
	alias := uniqueWindowsRoutePrivateNamespace("LowPreoccupy")
	boundaryName := alias + ".Administrators"
	locker := newPrivateWindowsRouteJournalLocker(alias, boundaryName, windowsRouteNamespaceMutexName, 2*time.Second)
	if err := locker.Open(); err != nil {
		t.Fatalf("open protected private namespace (Windows CI must run elevated): %v", err)
	}
	lock, err := locker.Lock()
	if err != nil {
		locker.Close()
		t.Fatal(err)
	}
	if err := lock.unlock(); err != nil {
		locker.Close()
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsRouteJournalProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		windowsRouteJournalHelperEnv+"=low-preoccupy-private-namespace",
		"TACHYON_ROUTE_TEST_NAMESPACE_ALIAS="+alias,
		"TACHYON_ROUTE_TEST_BOUNDARY_NAME="+boundaryName,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		locker.Close()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		locker.Close()
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		locker.Close()
		t.Fatal(err)
	}
	output := bufio.NewScanner(stdout)
	var stdoutLines []string
	ready := false
	for output.Scan() {
		stdoutLines = append(stdoutLines, output.Text())
		if output.Text() == "READY" {
			ready = true
			break
		}
	}
	if !ready {
		locker.Close()
		stdin.Close()
		waitErr := cmd.Wait()
		t.Fatalf(
			"low-privilege namespace helper did not become ready: exit=%d wait=%v scanner=%v stdout=%q stderr=%q",
			cmd.ProcessState.ExitCode(), waitErr, output.Err(), strings.Join(stdoutLines, "\n"), stderr.String(),
		)
	}

	if err := locker.Close(); err != nil {
		stdin.Close()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	restarted := newPrivateWindowsRouteJournalLocker(alias, boundaryName, windowsRouteNamespaceMutexName, 2*time.Second)
	if err := restarted.Open(); err != nil {
		stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("low-privilege same-alias namespace preoccupied Core restart: %v", err)
	}
	lock, err = restarted.Lock()
	if err == nil {
		err = lock.unlock()
	}
	err = errors.Join(err, restarted.Close())
	_, _ = io.WriteString(stdin, "release\n")
	_ = stdin.Close()
	for output.Scan() {
		stdoutLines = append(stdoutLines, output.Text())
	}
	err = errors.Join(err, output.Err(), cmd.Wait())
	if err != nil {
		t.Fatalf(
			"restart while low-privilege same-alias namespace exists: %v; exit=%d stdout=%q stderr=%q",
			err, cmd.ProcessState.ExitCode(), strings.Join(stdoutLines, "\n"), stderr.String(),
		)
	}
}

func TestWindowsRouteJournalRestrictedTokenCreatesUsersPrivateNamespace(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := createNonAdminRestrictedToken(admins)
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()
	if err := windows.SetThreadToken(nil, restricted); err != nil {
		t.Fatal(err)
	}
	defer windows.RevertToSelf()
	if member, err := restricted.IsMember(admins); err != nil || member {
		t.Fatalf("restricted helper still belongs to Administrators: member=%v error=%v", member, err)
	}

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	alias := uniqueWindowsRoutePrivateNamespace("RestrictedToken")
	namespace, err := openWindowsPrivateNamespace(alias, alias+".Users", users, nil)
	if err != nil {
		t.Fatalf("create Users-boundary private namespace under restricted token: %v", err)
	}
	defer namespace.Close(true)
	name, err := windows.UTF16PtrFromString(alias + `\` + windowsRouteNamespaceMutexName)
	if err != nil {
		t.Fatal(err)
	}
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		t.Fatal(err)
	}
	if err := windows.CloseHandle(mutex); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsRouteJournalMachineMutexMultiProcess(t *testing.T) {
	keyPath := uniqueWindowsRouteJournalTestKey("MultiProcess")
	storage := &registryWindowsRouteJournalStorage{root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State"}
	cleanupWindowsRouteJournalTestKey(t, keyPath)
	t.Cleanup(func() { cleanupWindowsRouteJournalTestKey(t, keyPath) })
	journal := &windowsRouteJournal{storage: storage, locker: &protectedWindowsRouteJournalLocker{timeout: windowsRouteLockTimeout}}
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

	foreignCases := []struct {
		state  string
		luid   uint64
		prefix netip.Prefix
	}{
		{state: "stale", luid: 2000, prefix: netip.MustParsePrefix("198.51.101.0/24")},
		{state: "live", luid: 2001, prefix: netip.MustParsePrefix("198.51.102.0/24")},
		{state: "error", luid: 2002, prefix: netip.MustParsePrefix("198.51.103.0/24")},
	}
	lock, err = journal.locker.Lock()
	if err != nil {
		t.Fatal(err)
	}
	data, err = journal.load()
	if err == nil {
		for _, foreign := range foreignCases {
			owner := &windowsRouteOperator{interfaceLUID: foreign.luid, interfaceIdx: uint32(foreign.luid)}
			txnID, txnErr := newWindowsRouteTransactionID()
			if txnErr != nil {
				err = txnErr
				break
			}
			data.Entries = append(data.Entries, newWindowsRouteJournalEntry(owner, foreign.prefix, txnID, windowsRouteActive))
		}
		if err == nil {
			err = journal.save(data)
		}
	}
	err = errors.Join(err, lock.unlock())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	for _, foreign := range foreignCases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsRouteJournalProcessHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(),
			windowsRouteJournalHelperEnv+"=reconcile-foreign",
			"TACHYON_ROUTE_JOURNAL_TEST_KEY="+keyPath,
			"TACHYON_ROUTE_JOURNAL_TEST_MARKER=3000",
			"TACHYON_ROUTE_JOURNAL_TEST_FOREIGN_LUID="+strconv.FormatUint(foreign.luid, 10),
			"TACHYON_ROUTE_JOURNAL_TEST_PREFIX="+foreign.prefix.String(),
			"TACHYON_ROUTE_JOURNAL_TEST_FOREIGN_STATE="+foreign.state,
		)
		if wire, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s foreign-LUID reconcile helper: %v\n%s", foreign.state, err, wire)
		}
	}

	reopened := &windowsRouteJournal{storage: storage, locker: &protectedWindowsRouteJournalLocker{timeout: windowsRouteLockTimeout}}
	t.Cleanup(func() { _ = reopened.Close() })
	lock, err = reopened.locker.Lock()
	if err != nil {
		t.Fatal(err)
	}
	data, loadErr = reopened.load()
	unlockErr = lock.unlock()
	if err := errors.Join(loadErr, unlockErr); err != nil {
		t.Fatal(err)
	}
	foreignRemaining := make(map[uint64]bool)
	for _, entry := range data.Entries {
		if entry.InterfaceLUID == 2000 {
			t.Fatal("stale foreign owner survived cross-process reconcile")
		}
		if entry.InterfaceLUID == 2001 || entry.InterfaceLUID == 2002 {
			foreignRemaining[entry.InterfaceLUID] = true
		}
	}
	if !foreignRemaining[2001] || !foreignRemaining[2002] {
		t.Fatalf("live/query-error owners were not retained: %v", foreignRemaining)
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
	if action == "low-preoccupy-private-namespace" {
		runLowPrivilegePrivateNamespaceHelper(t)
		return
	}
	keyPath := os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_KEY")
	storage := &registryWindowsRouteJournalStorage{
		root: registry.LOCAL_MACHINE, keyPath: keyPath, valueName: "State",
	}
	var locker windowsRouteJournalLocker = &protectedWindowsRouteJournalLocker{timeout: windowsRouteLockTimeout}
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
	if action == "reconcile-foreign" {
		runForeignLUIDReconcileHelper(t, journal)
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

func uniqueWindowsRoutePrivateNamespace(label string) string {
	return fmt.Sprintf("TachyonRouteJournalTest%s%d%d", label, windows.GetCurrentProcessId(), time.Now().UnixNano())
}

func runLowPrivilegePrivateNamespaceHelper(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	logWindowsRouteJournalHelperStage("create-administrators-sid")
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	logWindowsRouteJournalHelperStage("create-restricted-token")
	restricted, err := createNonAdminRestrictedToken(admins)
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()
	logWindowsRouteJournalHelperStage("impersonate-restricted-token")
	if err := windows.SetThreadToken(nil, restricted); err != nil {
		t.Fatal(err)
	}
	defer windows.RevertToSelf()
	logWindowsRouteJournalHelperStage("verify-administrators-disabled")
	if member, err := restricted.IsMember(admins); err != nil || member {
		t.Fatalf("restricted helper still belongs to Administrators: member=%v error=%v", member, err)
	}

	alias := os.Getenv("TACHYON_ROUTE_TEST_NAMESPACE_ALIAS")
	adminBoundary := os.Getenv("TACHYON_ROUTE_TEST_BOUNDARY_NAME")
	descriptor, err := newWindowsRouteNamespaceSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	logWindowsRouteJournalHelperStage("open-administrators-namespace-must-fail")
	if namespace, err := openExistingWindowsPrivateNamespace(alias, adminBoundary, admins); err == nil {
		namespace.Close(false)
		t.Fatal("restricted helper opened the Administrators private namespace")
	} else if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("restricted Administrators namespace open error = %v, want access denied", err)
	}
	logWindowsRouteJournalHelperStage("create-administrators-namespace-must-fail")
	if namespace, err := openWindowsPrivateNamespace(alias, adminBoundary, admins, descriptor); err == nil {
		namespace.Close(false)
		t.Fatal("restricted helper created or opened the Administrators private namespace")
	} else if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("restricted Administrators namespace create error = %v, want access denied", err)
	}

	logWindowsRouteJournalHelperStage("create-users-sid")
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	logWindowsRouteJournalHelperStage("create-users-boundary-same-alias-namespace")
	lowNamespace, err := openWindowsPrivateNamespace(alias, alias+".Users", users, nil)
	if err != nil {
		t.Fatalf("create low-privilege same-alias private namespace: %v", err)
	}
	defer lowNamespace.Close(false)
	logWindowsRouteJournalHelperStage("create-users-boundary-mutex")
	name, err := windows.UTF16PtrFromString(alias + `\` + windowsRouteNamespaceMutexName)
	if err != nil {
		t.Fatal(err)
	}
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		t.Fatal(err)
	}
	defer windows.CloseHandle(mutex)

	logWindowsRouteJournalHelperStage("ready")
	fmt.Println("READY")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
}

func logWindowsRouteJournalHelperStage(stage string) {
	fmt.Fprintf(os.Stderr, "route-journal-helper stage=%s\n", stage)
}

func createNonAdminRestrictedToken(admins *windows.SID) (windows.Token, error) {
	var process windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&process,
	); err != nil {
		return 0, fmt.Errorf("open process token for restriction: %w", err)
	}
	defer process.Close()

	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(
		process,
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&impersonation,
	); err != nil {
		return 0, fmt.Errorf("duplicate process token for restriction: %w", err)
	}
	defer impersonation.Close()
	type sidAndAttributes struct {
		SID        *windows.SID
		Attributes uint32
	}
	disabled := sidAndAttributes{SID: admins}
	var restricted windows.Token
	result, _, callErr := procCreateRestrictedToken.Call(
		uintptr(impersonation),
		1,
		1,
		uintptr(unsafe.Pointer(&disabled)),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	runtime.KeepAlive(admins)
	if result == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", windowsCallError(callErr))
	}
	return restricted, nil
}

func runForeignLUIDReconcileHelper(t *testing.T, journal *windowsRouteJournal) {
	t.Helper()
	marker, err := strconv.ParseUint(os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_MARKER"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	foreignLUID, err := strconv.ParseUint(os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_FOREIGN_LUID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := netip.ParsePrefix(os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_PREFIX"))
	if err != nil {
		t.Fatal(err)
	}
	wantState := os.Getenv("TACHYON_ROUTE_JOURNAL_TEST_FOREIGN_STATE")
	op := &windowsRouteOperator{
		interfaceLUID: marker,
		interfaceIdx:  uint32(marker),
		journal:       journal,
		api: windowsRouteAPI{
			initEntry: func(*windows.MibIpForwardRow2) {},
			get:       func(*windows.MibIpForwardRow2) error { return windows.ERROR_NOT_FOUND },
			interfaceExists: func(luid uint64, _ uint32) (bool, error) {
				if luid != foreignLUID {
					return true, nil
				}
				switch wantState {
				case "stale":
					return false, nil
				case "live":
					return true, nil
				case "error":
					return false, windows.ERROR_RETRY
				default:
					return false, fmt.Errorf("unknown foreign state %q", wantState)
				}
			},
		},
	}
	reconcileErr := journal.reconcile(context.Background(), op)
	switch wantState {
	case "stale":
		if reconcileErr != nil {
			t.Fatal(reconcileErr)
		}
		if err := journal.prepare(context.Background(), op, prefix); err != nil {
			t.Fatalf("claim destination after stale cross-process cleanup: %v", err)
		}
		if err := journal.release(op, prefix); err != nil {
			t.Fatal(err)
		}
	case "live":
		if reconcileErr != nil {
			t.Fatal(reconcileErr)
		}
		if err := journal.prepare(context.Background(), op, prefix); err == nil || !strings.Contains(err.Error(), "already owned") {
			t.Fatalf("live foreign owner claim error = %v", err)
		}
	case "error":
		if reconcileErr == nil || !strings.Contains(reconcileErr.Error(), "query foreign route owner") {
			t.Fatalf("foreign query failure = %v", reconcileErr)
		}
	}
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
