//go:build windows

package capturedudp

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
	"golang.org/x/sys/windows"
)

func TestWindowsNamedPipeClientProtocolAndReconnectBoundary(t *testing.T) {
	sid, integrity := currentWindowsTestIdentity(t)
	trustedBinary, trustedHash := currentWindowsTestBinary(t)
	registry := testRegistry(t, Limits{})
	sender := &fakeNamedPipeDatagramSender{sent: make(chan tgp.TunnelDatagram, 1)}
	server, err := NewNamedPipeServer(registry, NamedPipeConfig{
		Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{sid}, MinimumIntegrityRID: integrity,
		OperationTimeout: time.Second, AllowInsecureUserSID: true,
	}, sender)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Run(ctx) }()

	client, err := NewNamedPipeClient(NamedPipeClientConfig{
		Name: server.(*windowsNamedPipeServer).config.Name, OperationTimeout: time.Second,
		ReconnectMin: 10 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
		ServerSIDs: []string{sid}, MinimumServerIntegrityRID: integrity,
		TrustedServerBinary: trustedBinary, TrustedServerSHA256: trustedHash,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientResult := make(chan error, 1)
	go func() { clientResult <- client.Run(ctx) }()
	waitForNamedPipeClientHealth(t, client, func(health NamedPipeClientHealth) bool {
		return health.Connected && health.Authenticated
	})

	operationCtx, operationCancel := context.WithTimeout(ctx, 3*time.Second)
	pong, err := client.Ping(operationCtx, []byte("hello"))
	if err != nil || string(pong) != "hello" {
		operationCancel()
		t.Fatalf("ping response=%q error=%v", pong, err)
	}
	clear(pong)
	transaction, err := client.PrepareGeneration(operationCtx, 1)
	if err != nil {
		operationCancel()
		t.Fatal(err)
	}
	if err := client.CommitGeneration(operationCtx, transaction); err != nil {
		operationCancel()
		t.Fatal(err)
	}
	spec := testFlow(101, 1, "198.18.0.2:53000", "203.0.113.9:27015")
	lease, err := client.OpenFlow(operationCtx, spec)
	if err != nil {
		operationCancel()
		t.Fatal(err)
	}
	if err := client.SendDatagram(operationCtx, Datagram{
		FlowID: lease.FlowID, Generation: lease.Generation, LeaseNonce: lease.LeaseNonce,
		Sequence: 1, Payload: []byte("datagram"),
	}); err != nil {
		operationCancel()
		t.Fatal(err)
	}
	operationCancel()
	select {
	case received := <-sender.sent:
		if string(received.Payload) != "datagram" || received.Identity.FlowID != lease.FlowID {
			t.Fatalf("sender received = %+v", received)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Core sender did not receive datagram")
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseFlow(context.Background(), lease.Generation, lease.FlowID, lease.LeaseNonce); !errors.Is(err, ErrClosed) {
		// Close is expected to make new work fail; this assertion also checks
		// that a closed client never queues a new frame.
		t.Fatalf("closed client operation error = %v", err)
	}
	cancel()
	_ = server.Close()
	select {
	case err := <-clientResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not stop")
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestWindowsNamedPipeClientRejectsPipeNamePreemptionByUntrustedBinary(t *testing.T) {
	sid, integrity := currentWindowsTestIdentity(t)
	trustedBinary, _ := currentWindowsTestBinary(t)
	registry := testRegistry(t, Limits{})
	server, err := NewNamedPipeServer(registry, NamedPipeConfig{
		Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{sid}, MinimumIntegrityRID: integrity,
		OperationTimeout: time.Second, AllowInsecureUserSID: true,
	}, &fakeNamedPipeDatagramSender{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, openErr := openNamedPipeClient(ctx, NamedPipeClientConfig{
			Name: server.(*windowsNamedPipeServer).config.Name, ServerSIDs: []string{sid},
			MinimumServerIntegrityRID: integrity, TrustedServerBinary: trustedBinary,
			TrustedServerSHA256: strings.Repeat("0", 64),
			OperationTimeout:    time.Second,
		})
		if openErr == nil {
			_ = connection.Close()
			t.Fatal("untrusted server hash unexpectedly accepted")
		}
		if !errors.Is(openErr, ErrNamedPipeIdentity) && time.Now().After(deadline) {
			t.Fatalf("untrusted server error = %v", openErr)
		}
		if errors.Is(openErr, ErrNamedPipeIdentity) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("named pipe server did not become available")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWindowsNamedPipeDialIsSingleAttempt(t *testing.T) {
	sid, integrity := currentWindowsTestIdentity(t)
	trustedBinary, trustedHash := currentWindowsTestBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := openNamedPipeClient(ctx, NamedPipeClientConfig{
		Name: uniqueWindowsPipeName(t), ServerSIDs: []string{sid}, MinimumServerIntegrityRID: integrity,
		TrustedServerBinary: trustedBinary, TrustedServerSHA256: trustedHash,
		OperationTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("missing pipe unexpectedly connected")
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatalf("single dial attempt took %s", time.Since(started))
	}
}

func TestWindowsNamedPipeServerGrantsOnlyIdentityQueryRights(t *testing.T) {
	serviceSID := "S-1-5-80-1-2-3-4-5"
	if err := grantNamedPipeClientIdentityQueryAccess([]string{serviceSID}); err != nil {
		t.Fatal(err)
	}
	process, err := windows.OpenProcess(windows.READ_CONTROL, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	assertKernelObjectSIDAccess(t, process, serviceSID, namedPipeServerProcessQueryAccess)
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.READ_CONTROL, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	assertKernelObjectSIDAccess(t, windows.Handle(token), serviceSID, namedPipeServerTokenQueryAccess)
}

func assertKernelObjectSIDAccess(t *testing.T, handle windows.Handle, sidText string, expected windows.ACCESS_MASK) {
	t.Helper()
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read DACL: %v", err)
	}
	var actual windows.ACCESS_MASK
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.String() == sidText {
			actual |= ace.Mask
		}
	}
	if actual != expected {
		t.Fatalf("SID %s kernel-object access = %#x, want exact query-only %#x", sidText, actual, expected)
	}
}

func currentWindowsTestBinary(t *testing.T) (string, string) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := openImageFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	hash, err := sha256FileHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return path, hash
}

func waitForNamedPipeClientHealth(t *testing.T, client NamedPipeClient, predicate func(NamedPipeClientHealth) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if predicate(client.Health()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("client health condition not reached: %+v", client.Health())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
