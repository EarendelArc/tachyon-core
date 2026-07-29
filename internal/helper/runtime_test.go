package helper

import (
	"context"
	"errors"
	"sync"
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
