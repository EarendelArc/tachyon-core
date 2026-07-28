//go:build windows

package capturedudp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
	"golang.org/x/sys/windows"
)

func TestWindowsNamedPipeTGPClientManagerRelayDeliveryE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	relayTransport, err := tgp.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := tgp.NewRelay(tgp.RelayOptions{
		Transport: relayTransport, PacerPPS: 100000,
		Handler: tgp.RelayHandlerFunc(func(ctx context.Context, packet tgp.RelayPacket) error {
			datagram, err := tgp.ParseTunnelDatagram(packet.Payload)
			if err != nil {
				return err
			}
			datagram.Payload = append([]byte("relay:"), datagram.Payload...)
			wire, err := tgp.MarshalTunnelDatagram(datagram)
			if err != nil {
				return err
			}
			return packet.Session.SendPacket(ctx, 0, wire)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	relayResult := make(chan error, 1)
	go func() { relayResult <- relay.ListenAndServe(ctx) }()

	var sinkMu sync.RWMutex
	var sink NamedPipeServer
	manager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr: relayTransport.LocalAddr().String(), LocalAddr: "127.0.0.1:0",
		PacerPPS: 100000, HandshakeTimeout: time.Second,
		OnDatagram: func(ctx context.Context, datagram tgp.TunnelDatagram) error {
			sinkMu.RLock()
			server := sink
			sinkMu.RUnlock()
			if server == nil {
				return ErrTransportNotVerified
			}
			return server.DeliverReply(ctx, datagram)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	sid, integrity := currentWindowsTestIdentity(t)
	registry := testRegistry(t, Limits{})
	server, err := NewNamedPipeServer(registry, NamedPipeConfig{
		Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{sid}, MinimumIntegrityRID: integrity,
		OperationTimeout: 2 * time.Second, AllowInsecureUserSID: true,
	}, clientManagerNamedPipeSender{manager: manager})
	if err != nil {
		t.Fatal(err)
	}
	sinkMu.Lock()
	sink = server
	sinkMu.Unlock()
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Run(ctx) }()

	pipeName := server.(*windowsNamedPipeServer).config.Name
	handle := openWindowsPipeClient(t, pipeName)
	client := &windowsPipeConnection{handle: handle}
	hello, err := readNamedPipeFrame(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	requestID := uint64(1)
	auth := appendRequestID(nil, requestID)
	auth = append(auth, hello.Payload...)
	mustPipeStatusOK(t, ctx, client, pipeMessageAuthenticate, requestID, auth)
	requestID++
	prepare := appendRequestID(nil, requestID)
	prepare = appendUint64(prepare, 1)
	transaction := mustPipeResponseData(t, ctx, client, pipeMessagePrepareGeneration, requestID, prepare)
	requestID++
	commit := appendRequestID(nil, requestID)
	commit = append(commit, transaction...)
	mustPipeStatusOK(t, ctx, client, pipeMessageCommitGeneration, requestID, commit)

	spec := testFlow(77, 1, "198.18.0.2:53000", "203.0.113.9:27015")
	requestID++
	openFlow, err := encodePipeFlowSpec(requestID, spec)
	if err != nil {
		t.Fatal(err)
	}
	leaseWire := mustPipeResponseData(t, ctx, client, pipeMessageOpenFlow, requestID, openFlow)
	var lease FlowLease
	copy(lease.FlowID[:], leaseWire[:16])
	lease.Generation = binary.BigEndian.Uint64(leaseWire[16:24])
	copy(lease.LeaseNonce[:], leaseWire[24:40])
	requestID++
	datagram := appendRequestID(nil, requestID)
	datagram = append(datagram, lease.FlowID[:]...)
	datagram = appendUint64(datagram, lease.Generation)
	datagram = append(datagram, lease.LeaseNonce[:]...)
	datagram = appendUint64(datagram, 1)
	datagram = append(datagram, "ping"...)
	if err := writeNamedPipeFrame(ctx, client, namedPipeFrame{Type: pipeMessageDatagram, Payload: datagram}); err != nil {
		t.Fatal(err)
	}
	var gotResponse, gotDelivery bool
	for !gotResponse || !gotDelivery {
		frame, err := readNamedPipeFrame(ctx, client)
		if err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case pipeMessageResponse:
			responseID, operation, status, _, err := decodePipeResponse(frame)
			if err != nil || responseID != requestID || operation != pipeMessageDatagram || status != pipeStatusOK {
				t.Fatalf("datagram response id=%d operation=%d status=%d error=%v", responseID, operation, status, err)
			}
			gotResponse = true
		case pipeMessageDelivery:
			if len(frame.Payload) != 50 || !bytes.Equal(frame.Payload[:16], lease.FlowID[:]) ||
				binary.BigEndian.Uint64(frame.Payload[16:24]) != lease.Generation ||
				!bytes.Equal(frame.Payload[24:40], lease.LeaseNonce[:]) || string(frame.Payload[40:]) != "relay:ping" {
				t.Fatalf("invalid delivery payload %x", frame.Payload)
			}
			gotDelivery = true
		default:
			t.Fatalf("unexpected frame type %d", frame.Type)
		}
	}
	_ = windows.CloseHandle(handle)
	waitForCapturedUDPHealth(t, registry, func(health Health) bool {
		return !health.TransportAttached && !health.ControllerConnected && health.OpenFlows == 0
	})
	cancel()
	_ = server.Close()
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("named pipe server did not stop")
	}
	select {
	case err := <-relayResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not stop")
	}
}

type clientManagerNamedPipeSender struct {
	manager *tgp.ClientManager
}

func TestWindowsNamedPipeWriteBreakAllowsSecondClient(t *testing.T) {
	sid, integrity := currentWindowsTestIdentity(t)
	registry := testRegistry(t, Limits{})
	sender := &gatedNamedPipeDatagramSender{started: make(chan struct{}), release: make(chan struct{})}
	config := NamedPipeConfig{
		Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{sid}, MinimumIntegrityRID: integrity,
		OperationTimeout: time.Second, AllowInsecureUserSID: true,
	}
	server, err := NewNamedPipeServer(registry, config, sender)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Run(ctx) }()
	clientHandle := openWindowsPipeClient(t, config.Name)
	client := &windowsPipeConnection{handle: clientHandle}
	operationCtx, operationCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer operationCancel()
	hello, err := readNamedPipeFrame(operationCtx, client)
	if err != nil {
		t.Fatal(err)
	}
	requestID := uint64(1)
	auth := appendRequestID(nil, requestID)
	auth = append(auth, hello.Payload...)
	mustPipeStatusOK(t, operationCtx, client, pipeMessageAuthenticate, requestID, auth)
	requestID++
	prepare := appendRequestID(nil, requestID)
	prepare = appendUint64(prepare, 1)
	transaction := mustPipeResponseData(t, operationCtx, client, pipeMessagePrepareGeneration, requestID, prepare)
	requestID++
	commit := appendRequestID(nil, requestID)
	commit = append(commit, transaction...)
	mustPipeStatusOK(t, operationCtx, client, pipeMessageCommitGeneration, requestID, commit)
	spec := testFlow(9, 1, "198.18.0.2:53000", "203.0.113.9:27015")
	requestID++
	openFlow, err := encodePipeFlowSpec(requestID, spec)
	if err != nil {
		t.Fatal(err)
	}
	leaseWire := mustPipeResponseData(t, operationCtx, client, pipeMessageOpenFlow, requestID, openFlow)
	requestID++
	datagram := appendRequestID(nil, requestID)
	datagram = append(datagram, leaseWire[:16]...)
	datagram = append(datagram, leaseWire[16:24]...)
	datagram = append(datagram, leaseWire[24:40]...)
	datagram = appendUint64(datagram, 1)
	datagram = append(datagram, "break-write"...)
	if err := writeNamedPipeFrame(operationCtx, client, namedPipeFrame{Type: pipeMessageDatagram, Payload: datagram}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.started:
	case <-operationCtx.Done():
		t.Fatal(operationCtx.Err())
	}
	_ = windows.CloseHandle(clientHandle)
	close(sender.release)
	waitForCapturedUDPHealth(t, registry, func(health Health) bool {
		return !health.TransportAttached && !health.ControllerConnected && !health.Ready
	})
	replacement := openWindowsPipeClient(t, config.Name)
	replacementClient := &windowsPipeConnection{handle: replacement}
	replacementHello, err := readNamedPipeFrame(operationCtx, replacementClient)
	if err != nil || replacementHello.Type != pipeMessageHello {
		t.Fatalf("write-break reconnect hello type=%d error=%v", replacementHello.Type, err)
	}
	_ = windows.CloseHandle(replacement)
	cancel()
	_ = server.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after write-break reconnect")
	}
}

type gatedNamedPipeDatagramSender struct {
	started chan struct{}
	release chan struct{}
}

func (sender *gatedNamedPipeDatagramSender) SendDatagram(ctx context.Context, _ tgp.TunnelDatagram) error {
	select {
	case <-sender.started:
	default:
		close(sender.started)
	}
	select {
	case <-sender.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (sender clientManagerNamedPipeSender) SendDatagram(ctx context.Context, datagram tgp.TunnelDatagram) error {
	wire, err := tgp.MarshalTunnelDatagram(datagram)
	if err != nil {
		return err
	}
	return sender.manager.SendPacket(ctx, 0, wire)
}

func TestNamedPipeACLRequiresExplicitPreviewForUserSID(t *testing.T) {
	sid, _ := currentWindowsTestIdentity(t)
	config := NamedPipeConfig{Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{sid}}
	if _, _, _, err := buildNamedPipeSecurity(config); !errors.Is(err, ErrNamedPipeIdentity) {
		t.Fatalf("ordinary SID without preview error = %v", err)
	}
	config.AllowInsecureUserSID = true
	attributes, allowed, _, err := buildNamedPipeSecurity(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := allowed[sid]; !ok {
		t.Fatalf("canonical allowed SIDs = %#v", allowed)
	}
	sddl := attributes.SecurityDescriptor.String()
	if strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;AU)") || strings.Contains(sddl, ";;;BA)") {
		t.Fatalf("pipe ACL contains broad principal: %s", sddl)
	}
}

func TestNamedPipeRevertFailureInvokesFailStopAndNeverReturns(t *testing.T) {
	failStopCalled := make(chan error, 1)
	returned := atomic.Bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = verifyNamedPipePeerWithHooks(0, nil, 0, namedPipeIdentityHooks{
			impersonate: func(windows.Handle) error { return nil },
			inspect: func(map[string]struct{}, uint32) (namedPipePeerIdentity, error) {
				return namedPipePeerIdentity{SID: "S-1-5-18", IntegrityRID: mandatorySystemRID}, nil
			},
			revert:   func() error { return errors.New("injected revert failure") },
			failStop: func(err error) { failStopCalled <- err },
		})
		returned.Store(true)
	}()
	select {
	case err := <-failStopCalled:
		if !errors.Is(err, ErrNamedPipeIdentity) {
			t.Fatalf("fail-stop error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fail-stop hook was not invoked")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("locked impersonation goroutine did not terminate")
	}
	if returned.Load() {
		t.Fatal("verification returned after RevertToSelf failure")
	}
}

func TestWindowsNamedPipeEndToEndSingleInstanceIdleAndEOFCleanup(t *testing.T) {
	sid, integrity := currentWindowsTestIdentity(t)
	registry := testRegistry(t, Limits{})
	config := NamedPipeConfig{
		Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{sid}, MinimumIntegrityRID: integrity,
		OperationTimeout: 100 * time.Millisecond, IdleTimeout: 0, AllowInsecureUserSID: true,
	}
	sender := &fakeNamedPipeDatagramSender{}
	server, err := NewNamedPipeServer(registry, config, sender)
	if err != nil {
		t.Fatalf("create named pipe server: %v", err)
	}
	defer server.Close()
	if second, err := NewNamedPipeServer(registry, config, sender); err == nil {
		_ = second.Close()
		t.Fatal("second named pipe instance unexpectedly succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Run(ctx) }()

	client := openWindowsPipeClient(t, config.Name)
	clientIO := &windowsPipeConnection{handle: client}
	helloContext, helloCancel := context.WithTimeout(context.Background(), 2*time.Second)
	hello, err := readNamedPipeFrame(helloContext, clientIO)
	helloCancel()
	if err != nil || hello.Type != pipeMessageHello || len(hello.Payload) != SessionTokenSize {
		t.Fatalf("hello type=%d length=%d err=%v", hello.Type, len(hello.Payload), err)
	}
	requestID := uint64(1)
	auth := appendRequestID(nil, requestID)
	auth = append(auth, hello.Payload...)
	operationContext, operationCancel := context.WithTimeout(context.Background(), 2*time.Second)
	mustPipeStatusOK(t, operationContext, clientIO, pipeMessageAuthenticate, requestID, auth)
	clear(auth)
	clear(hello.Payload)

	requestID++
	prepare := appendRequestID(nil, requestID)
	prepare = appendUint64(prepare, 1)
	transaction := mustPipeResponseData(t, operationContext, clientIO, pipeMessagePrepareGeneration, requestID, prepare)
	requestID++
	commit := appendRequestID(nil, requestID)
	commit = append(commit, transaction...)
	mustPipeStatusOK(t, operationContext, clientIO, pipeMessageCommitGeneration, requestID, commit)
	if !registry.Health().Ready {
		t.Fatal("registry was not ready after authenticated generation commit")
	}

	// Exceed the write deadline while leaving idle reads unlimited.
	time.Sleep(250 * time.Millisecond)
	requestID++
	ping := appendRequestID(nil, requestID)
	ping = append(ping, "idle"...)
	if err := writeNamedPipeFrame(operationContext, clientIO, namedPipeFrame{Type: pipeMessagePing, Payload: ping}); err != nil {
		t.Fatal(err)
	}
	pong, err := readNamedPipeFrame(operationContext, clientIO)
	if err != nil || pong.Type != pipeMessagePong || string(pong.Payload[8:]) != "idle" {
		t.Fatalf("pong=%+v err=%v", pong, err)
	}
	operationCancel()

	// Closing the client handle models helper EOF/crash. The server must revoke
	// controller state before accepting a replacement connection.
	_ = windows.CloseHandle(client)
	waitForCapturedUDPHealth(t, registry, func(health Health) bool {
		return !health.TransportAttached && !health.ControllerConnected && !health.Ready && health.ActiveGeneration == 0
	})
	replacement := openWindowsPipeClient(t, config.Name)
	replacementIO := &windowsPipeConnection{handle: replacement}
	reconnectCtx, reconnectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	reconnectHello, err := readNamedPipeFrame(reconnectCtx, replacementIO)
	reconnectCancel()
	if err != nil || reconnectHello.Type != pipeMessageHello {
		t.Fatalf("EOF reconnect hello type=%d err=%v", reconnectHello.Type, err)
	}
	clear(reconnectHello.Payload)
	_ = windows.CloseHandle(replacement)
	cancel()
	_ = server.Close()
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("named pipe server did not stop")
	}
}

func TestWindowsNamedPipeIdleExpiryAllowsReconnect(t *testing.T) {
	sid, integrity := currentWindowsTestIdentity(t)
	registry := testRegistry(t, Limits{})
	config := NamedPipeConfig{
		Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{sid}, MinimumIntegrityRID: integrity,
		OperationTimeout: time.Second, IdleTimeout: 75 * time.Millisecond, AllowInsecureUserSID: true,
	}
	server, err := NewNamedPipeServer(registry, config, &fakeNamedPipeDatagramSender{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Run(ctx) }()
	first := openWindowsPipeClient(t, config.Name)
	firstIO := &windowsPipeConnection{handle: first}
	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if _, err := readNamedPipeFrame(readCtx, firstIO); err != nil {
		t.Fatal(err)
	}
	readCancel()
	time.Sleep(200 * time.Millisecond)
	_ = windows.CloseHandle(first)
	second := openWindowsPipeClient(t, config.Name)
	secondIO := &windowsPipeConnection{handle: second}
	readCtx, readCancel = context.WithTimeout(context.Background(), 2*time.Second)
	hello, err := readNamedPipeFrame(readCtx, secondIO)
	readCancel()
	if err != nil || hello.Type != pipeMessageHello {
		t.Fatalf("idle reconnect hello type=%d err=%v", hello.Type, err)
	}
	clear(hello.Payload)
	_ = windows.CloseHandle(second)
	cancel()
	_ = server.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after idle reconnect")
	}
}

func TestWindowsNamedPipeWrongSIDIsDeniedByACL(t *testing.T) {
	currentSID, integrity := currentWindowsTestIdentity(t)
	wrongSID := "S-1-5-19"
	if currentSID == wrongSID {
		wrongSID = "S-1-5-20"
	}
	registry := testRegistry(t, Limits{})
	config := NamedPipeConfig{
		Name: uniqueWindowsPipeName(t), AllowedSIDs: []string{wrongSID}, MinimumIntegrityRID: integrity,
		OperationTimeout: time.Second,
	}
	server, err := NewNamedPipeServer(registry, config, &fakeNamedPipeDatagramSender{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if handle, err := tryOpenWindowsPipeClient(config.Name); err == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("current user opened pipe restricted to a different service SID")
	}
	if health := registry.Health(); health.TransportAttached || health.ControllerConnected || health.Ready {
		t.Fatalf("denied client changed registry health = %+v", health)
	}
}

func TestWindowsNamedPipeRejectsLowIntegrityPolicy(t *testing.T) {
	if err := validateNamedPipeIntegrity(mandatoryLowRID, mandatoryMediumRID); !errors.Is(err, ErrNamedPipeIdentity) {
		t.Fatalf("low integrity error = %v", err)
	}
	if err := validateNamedPipeIntegrity(mandatoryHighRID, mandatoryMediumRID); err != nil {
		t.Fatalf("high integrity error = %v", err)
	}
}

func TestWindowsNamedPipeMatchesEnabledServiceGroup(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-123-456-789-10-11")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]struct{}{serviceSID.String(): {}}
	groups := []windows.SIDAndAttributes{{Sid: serviceSID, Attributes: windows.SE_GROUP_ENABLED}}
	if got := matchRestrictedHelperGroup(allowed, groups, true); got != serviceSID.String() {
		t.Fatalf("enabled service group match = %q", got)
	}
	groups[0].Attributes = windows.SE_GROUP_USE_FOR_DENY_ONLY
	if got := matchRestrictedHelperGroup(allowed, groups, true); got != "" {
		t.Fatalf("deny-only service group matched as %q", got)
	}
}

func currentWindowsTestIdentity(t *testing.T) (string, uint32) {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	integrity, err := tokenIntegrityRID(token)
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String(), integrity
}

func uniqueWindowsPipeName(t *testing.T) string {
	t.Helper()
	return `\\.\pipe\Tachyon\test-` + strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000000")
}

func openWindowsPipeClient(t *testing.T, name string) windows.Handle {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		handle, err := tryOpenWindowsPipeClient(name)
		if err == nil {
			return handle
		}
		if time.Now().After(deadline) {
			t.Fatalf("open named pipe client: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func tryOpenWindowsPipeClient(name string) (windows.Handle, error) {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(namePointer, namedPipeClientAccess, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IMPERSONATION, 0)
}

func waitForCapturedUDPHealth(t *testing.T, registry *Registry, predicate func(Health) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if predicate(registry.Health()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("health condition not reached: %+v", registry.Health())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
