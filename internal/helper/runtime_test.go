package helper

import (
	"context"
	"errors"
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
	contract.CancelIOCTL = contract.CaptureIOCTL
	return contract
}

func (provider *lifecycleProvider) Contract() WFPDriverContract { return RequiredWFPDriverContract() }

func (provider *lifecycleProvider) Start(context.Context, CaptureCallbacks) error {
	close(provider.started)
	return provider.startErr
}

func (provider *lifecycleProvider) Stop(context.Context) error {
	close(provider.stopped)
	return nil
}

func (provider *lifecycleProvider) Health() ProviderHealth {
	return ProviderHealth{Status: "ready", Verified: true, Capabilities: CaptureCapabilities{
		FlowCapture: true, DatagramCapture: true, KernelInjection: true, Cancelable: true,
	}}
}

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
	runtime := &Runtime{provider: provider, injector: injector}
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
	runtime := &Runtime{provider: provider, injector: injector}
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
		config: Config{OperationTimeout: 30 * time.Millisecond, FailStop: func(context.Context) error {
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
	return capturedudp.NamedPipeClientHealth{}
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
