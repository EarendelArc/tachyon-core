package helper

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/capturedudp"
)

type lifecycleProvider struct {
	startErr error
	started  chan struct{}
	stopped  chan struct{}
}

type invalidContractProvider struct{ lifecycleProvider }

func (provider *invalidContractProvider) Contract() WFPDriverContract {
	contract := RequiredWFPDriverContract()
	contract.VerdictIOCTL = contract.DequeueIOCTL
	return contract
}

func (provider *lifecycleProvider) Contract() WFPDriverContract { return RequiredWFPDriverContract() }

func (provider *lifecycleProvider) Start(ctx context.Context, _ CaptureCallbacks) error {
	close(provider.started)
	if provider.startErr != nil {
		return provider.startErr
	}
	<-ctx.Done()
	return nil
}

func (provider *lifecycleProvider) Stop(context.Context) error {
	close(provider.stopped)
	return nil
}

func (provider *lifecycleProvider) Health() ProviderHealth {
	return ProviderHealth{Status: "ready", Verified: true, Capabilities: CaptureCapabilities{
		FlowCapture: true, DatagramCapture: true, ProcessIdentity: true, PerFlowMTU: true, Cancelable: true,
	}}
}

func (provider *lifecycleProvider) ActivatePolicy(context.Context, WFPPolicy) error { return nil }
func (provider *lifecycleProvider) DisablePolicy(context.Context) error             { return nil }

type lifecycleInjector struct {
	closed chan struct{}
}

type unresponsiveStopProvider struct {
	lifecycleProvider
	stopCalls atomic.Int32
	entered   chan struct{}
	release   chan struct{}
}

func (provider *unresponsiveStopProvider) Stop(context.Context) error {
	provider.stopCalls.Add(1)
	select {
	case <-provider.entered:
	default:
		close(provider.entered)
	}
	<-provider.release
	return nil
}

func (injector *lifecycleInjector) Inject(context.Context, Delivery) error { return nil }

func (injector *lifecycleInjector) CloseFlow(context.Context, FlowIdentity) error { return nil }

func (injector *lifecycleInjector) Close(context.Context) error {
	close(injector.closed)
	return nil
}

func TestRuntimeStopsProviderAfterPartialStartFailure(t *testing.T) {
	provider := &lifecycleProvider{startErr: errors.New("start failed"), started: make(chan struct{}), stopped: make(chan struct{})}
	injector := &lifecycleInjector{closed: make(chan struct{})}
	runtime := &Runtime{config: Config{Policy: fixturePolicy()}, provider: provider, injector: injector}
	runtime.client = &blockingTestClient{}
	if err := runtime.Run(context.Background()); err == nil {
		t.Fatal("partial provider start unexpectedly succeeded")
	}
	select {
	case <-provider.stopped:
	case <-time.After(time.Second):
		t.Fatal("provider Stop was not called after Start failure")
	}
	select {
	case <-injector.closed:
	case <-time.After(time.Second):
		t.Fatal("injector Close was not called after Start failure")
	}
}

func TestRuntimeRejectsInvalidProviderContractAndStopsProvider(t *testing.T) {
	provider := &invalidContractProvider{lifecycleProvider: lifecycleProvider{started: make(chan struct{}), stopped: make(chan struct{})}}
	injector := &lifecycleInjector{closed: make(chan struct{})}
	runtime := &Runtime{config: Config{Policy: fixturePolicy()}, provider: provider, injector: injector}
	runtime.client = &blockingTestClient{}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrInvalidCaptureContract) {
		t.Fatalf("invalid provider contract error = %v", err)
	}
	select {
	case <-provider.stopped:
	case <-time.After(time.Second):
		t.Fatal("provider Stop was not called after contract rejection")
	}
	if health := runtime.Health(); health.ProviderCleanup != "confirmed" {
		t.Fatalf("provider cleanup state = %q", health.ProviderCleanup)
	}
}

func TestRuntimeProviderStopHasOneOwnerAndFailsClosedAtDeadline(t *testing.T) {
	provider := &unresponsiveStopProvider{lifecycleProvider: lifecycleProvider{
		started: make(chan struct{}), stopped: make(chan struct{}),
	}, entered: make(chan struct{}), release: make(chan struct{})}
	injector := &lifecycleInjector{closed: make(chan struct{})}
	var failStopCalls atomic.Int32
	runtime := &Runtime{
		config: Config{OperationTimeout: 30 * time.Millisecond, Policy: fixturePolicy(), FailStop: func(context.Context) error {
			failStopCalls.Add(1)
			return nil
		}},
		provider: provider, injector: injector, client: &blockingTestClient{},
		failStop: func(context.Context) error {
			failStopCalls.Add(1)
			return nil
		},
	}
	runResult := make(chan error, 1)
	go func() { runResult <- runtime.Run(context.Background()) }()
	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("provider did not start")
	}
	start := time.Now()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	shutdownResult := make(chan error, 8)
	var waitGroup sync.WaitGroup
	for range 8 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			shutdownResult <- runtime.Shutdown(shutdownContext)
		}()
	}
	waitGroup.Wait()
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("shutdown blocked past absolute deadline: %s", elapsed)
	}
	for range 8 {
		if err := <-shutdownResult; !errors.Is(err, ErrRuntimeStopTimeout) {
			t.Fatalf("shutdown error = %v, want stop timeout", err)
		}
	}
	if provider.stopCalls.Load() != 1 {
		t.Fatalf("provider Stop calls = %d, want 1", provider.stopCalls.Load())
	}
	if failStopCalls.Load() != 1 {
		t.Fatalf("fail-stop calls = %d, want 1", failStopCalls.Load())
	}
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		t.Fatal("provider Stop was not started")
	}
	select {
	case err := <-runResult:
		if !errors.Is(err, ErrRuntimeStopTimeout) {
			t.Fatalf("Run error = %v, want stop timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after fail-stop")
	}
	close(provider.release)
}

type blockingTestClient struct {
	mu     sync.Mutex
	closed chan struct{}
	health capturedudp.NamedPipeClientHealth
}

func (client *blockingTestClient) Run(ctx context.Context) error {
	client.mu.Lock()
	if client.closed == nil {
		client.closed = make(chan struct{})
	}
	closed := client.closed
	client.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-closed:
		return nil
	}
}

func (client *blockingTestClient) Close() error {
	client.mu.Lock()
	if client.closed == nil {
		client.closed = make(chan struct{})
	}
	select {
	case <-client.closed:
	default:
		close(client.closed)
	}
	client.mu.Unlock()
	return nil
}

func (client *blockingTestClient) Health() capturedudp.NamedPipeClientHealth {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.health
}
func (client *blockingTestClient) Ping(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (client *blockingTestClient) PrepareGeneration(context.Context, uint64) (capturedudp.GenerationTransaction, error) {
	return capturedudp.GenerationTransaction{}, errors.New("not used")
}
func (client *blockingTestClient) CommitGeneration(context.Context, capturedudp.GenerationTransaction) error {
	return errors.New("not used")
}
func (client *blockingTestClient) AbortGeneration(context.Context, capturedudp.GenerationTransaction) error {
	return errors.New("not used")
}
func (client *blockingTestClient) DisableGeneration(context.Context, uint64) error {
	return errors.New("not used")
}
func (client *blockingTestClient) OpenFlow(context.Context, capturedudp.FlowSpec) (capturedudp.FlowLease, error) {
	return capturedudp.FlowLease{}, errors.New("not used")
}
func (client *blockingTestClient) SendDatagram(context.Context, capturedudp.Datagram) error {
	return errors.New("not used")
}
func (client *blockingTestClient) CloseFlow(context.Context, uint64, capturedudp.FlowID, capturedudp.LeaseNonce) error {
	return errors.New("not used")
}

func TestRuntimeHealthIncludesPipeFailureDiagnostics(t *testing.T) {
	runtime := &Runtime{
		provider: NewUnavailableCaptureProvider(),
		client: &blockingTestClient{health: capturedudp.NamedPipeClientHealth{
			Stage: "connect_failed", Attempt: 4, Reconnects: 4,
			LastError: "captured UDP named pipe peer identity rejected: open server process: access denied",
		}},
	}
	health := runtime.Health()
	if health.Stage != "connect_failed" || health.Attempt != 4 || health.Reconnects != 4 {
		t.Fatalf("structured pipe health was not propagated: %+v", health)
	}
	if !strings.Contains(health.LastError, "open server process") {
		t.Fatalf("pipe failure detail was lost: %+v", health)
	}
}

type orderedRuntimeLog struct {
	mu      sync.Mutex
	entries []string
}

func (log *orderedRuntimeLog) add(entry string) {
	log.mu.Lock()
	log.entries = append(log.entries, entry)
	log.mu.Unlock()
}

func (log *orderedRuntimeLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.entries...)
}

type transactionalTestProvider struct {
	log         *orderedRuntimeLog
	activated   chan struct{}
	activateErr error
}

func (provider *transactionalTestProvider) Contract() WFPDriverContract {
	return RequiredWFPDriverContract()
}
func (provider *transactionalTestProvider) Health() ProviderHealth {
	return ProviderHealth{Status: "ready", Verified: true, Capabilities: RequiredWFPDriverContract().Capabilities}
}
func (provider *transactionalTestProvider) Start(ctx context.Context, _ CaptureCallbacks) error {
	provider.log.add("provider-start")
	<-ctx.Done()
	return nil
}
func (provider *transactionalTestProvider) Stop(context.Context) error {
	provider.log.add("provider-stop")
	return nil
}
func (provider *transactionalTestProvider) ActivatePolicy(context.Context, WFPPolicy) error {
	provider.log.add("provider-activate")
	if provider.activateErr == nil {
		select {
		case <-provider.activated:
		default:
			close(provider.activated)
		}
	}
	return provider.activateErr
}
func (provider *transactionalTestProvider) DisablePolicy(context.Context) error {
	provider.log.add("provider-disable")
	return nil
}

type transactionalTestClient struct {
	log    *orderedRuntimeLog
	mu     sync.Mutex
	health capturedudp.NamedPipeClientHealth
	closed chan struct{}
}

func newTransactionalTestClient(log *orderedRuntimeLog) *transactionalTestClient {
	return &transactionalTestClient{log: log, health: capturedudp.NamedPipeClientHealth{Connected: true, Authenticated: true, Stage: "authenticated"}, closed: make(chan struct{})}
}
func (client *transactionalTestClient) Run(ctx context.Context) error {
	client.log.add("pipe-start")
	select {
	case <-ctx.Done():
		return nil
	case <-client.closed:
		return nil
	}
}
func (client *transactionalTestClient) Close() error {
	client.mu.Lock()
	select {
	case <-client.closed:
	default:
		close(client.closed)
	}
	client.mu.Unlock()
	return nil
}
func (client *transactionalTestClient) Health() capturedudp.NamedPipeClientHealth {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.health
}
func (client *transactionalTestClient) disconnect() {
	client.mu.Lock()
	client.health.Connected, client.health.Authenticated, client.health.Stage = false, false, "session_failed"
	client.mu.Unlock()
}
func (client *transactionalTestClient) Ping(context.Context, []byte) ([]byte, error) { return nil, nil }
func (client *transactionalTestClient) PrepareGeneration(_ context.Context, generation uint64) (capturedudp.GenerationTransaction, error) {
	client.log.add("core-prepare")
	return capturedudp.GenerationTransaction{Generation: generation, ID: [16]byte{1}}, nil
}
func (client *transactionalTestClient) CommitGeneration(context.Context, capturedudp.GenerationTransaction) error {
	client.log.add("core-commit")
	return nil
}
func (client *transactionalTestClient) AbortGeneration(context.Context, capturedudp.GenerationTransaction) error {
	client.log.add("core-abort")
	return nil
}
func (client *transactionalTestClient) DisableGeneration(context.Context, uint64) error {
	client.log.add("core-disable")
	return nil
}
func (client *transactionalTestClient) OpenFlow(context.Context, capturedudp.FlowSpec) (capturedudp.FlowLease, error) {
	return capturedudp.FlowLease{}, nil
}
func (client *transactionalTestClient) SendDatagram(context.Context, capturedudp.Datagram) error {
	return nil
}
func (client *transactionalTestClient) CloseFlow(context.Context, uint64, capturedudp.FlowID, capturedudp.LeaseNonce) error {
	return nil
}

func TestRuntimeActivatesAfterBothHandshakesAndDisablesOnDisconnect(t *testing.T) {
	log := &orderedRuntimeLog{}
	provider := &transactionalTestProvider{log: log, activated: make(chan struct{})}
	client := newTransactionalTestClient(log)
	runtime := &Runtime{config: Config{Policy: fixturePolicy(), OperationTimeout: 250 * time.Millisecond},
		provider: provider, injector: &lifecycleInjector{closed: make(chan struct{})}, client: client, failStop: func(context.Context) error { return nil }}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	select {
	case <-provider.activated:
	case <-time.After(time.Second):
		t.Fatal("policy transaction did not activate")
	}
	client.disconnect()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRuntimePipeDisconnected) {
			t.Fatalf("run error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop after authenticated pipe disconnect")
	}
	entries := strings.Join(log.snapshot(), ",")
	for _, ordered := range []string{"core-prepare,provider-activate,core-commit", "provider-disable", "core-disable", "provider-stop"} {
		if !strings.Contains(entries, ordered) {
			t.Fatalf("transaction log %q missing %q", entries, ordered)
		}
	}
}

func TestRuntimeActivationFailureAbortsAndDisables(t *testing.T) {
	log := &orderedRuntimeLog{}
	provider := &transactionalTestProvider{log: log, activated: make(chan struct{}), activateErr: errors.New("activation rejected")}
	client := newTransactionalTestClient(log)
	runtime := &Runtime{config: Config{Policy: fixturePolicy(), OperationTimeout: 250 * time.Millisecond},
		provider: provider, injector: &lifecycleInjector{closed: make(chan struct{})}, client: client, failStop: func(context.Context) error { return nil }}
	if err := runtime.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "activation rejected") {
		t.Fatalf("run error = %v", err)
	}
	entries := strings.Join(log.snapshot(), ",")
	for _, required := range []string{"core-prepare", "provider-activate", "core-abort", "provider-disable", "core-disable"} {
		if !strings.Contains(entries, required) {
			t.Fatalf("transaction log %q missing %q", entries, required)
		}
	}
}
