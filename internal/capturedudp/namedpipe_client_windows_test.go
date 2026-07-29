//go:build windows

package capturedudp

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

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
