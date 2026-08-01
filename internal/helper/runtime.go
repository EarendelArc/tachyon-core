package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/capturedudp"
)

var (
	ErrInvalidCaptureContract = errors.New("capture provider contract is not an exact supported contract")
	ErrRuntimeStopTimeout     = errors.New("helper runtime shutdown timed out")
)

type Config struct {
	PipeName string
	// AllowedSIDs is used only by the test-only Core pipe endpoint. The
	// production helper never creates a server pipe.
	AllowedSIDs               []string
	ServerSIDs                []string
	MinimumServerIntegrityRID uint32
	TrustedServerBinary       string
	TrustedServerSHA256       string
	OperationTimeout          time.Duration
	ReconnectMin              time.Duration
	ReconnectMax              time.Duration
	ServiceName               string
	DiagnosticServiceSID      string
	DiagnosticOwnerSID        string
	DiagnosticFile            string
	DiagnosticOverride        bool
	TestReadyFile             string
	// FailStop is invoked only after the sole provider shutdown operation has
	// exceeded its absolute deadline. Production Windows uses TerminateProcess;
	// tests inject a harmless implementation.
	FailStop func(context.Context) error
	Provider CaptureProvider
	Injector Injector
}

type Health struct {
	Status              string              `json:"status"`
	Reason              string              `json:"reason"`
	CaptureProvider     string              `json:"capture_provider"`
	CaptureCapabilities CaptureCapabilities `json:"capture_capabilities"`
	PipeConnected       bool                `json:"pipe_connected"`
	Authenticated       bool                `json:"authenticated"`
	Stage               string              `json:"stage"`
	Attempt             uint64              `json:"attempt"`
	Reconnects          uint64              `json:"reconnects"`
	WFPContractVersion  string              `json:"wfp_contract_version"`
	ServiceSIDPresent   bool                `json:"service_sid_present"`
	RestrictedSIDCount  int                 `json:"restricted_sid_count"`
	PID                 int                 `json:"pid"`
	UpdatedAt           string              `json:"updated_at"`
	Lifecycle           string              `json:"lifecycle"`
	LastError           string              `json:"last_error,omitempty"`
	StopTimedOut        bool                `json:"stop_timed_out"`
	ProviderCleanup     string              `json:"provider_cleanup"`
}

type Runtime struct {
	config     Config
	provider   CaptureProvider
	injector   Injector
	client     capturedudp.NamedPipeClient
	diagnostic diagnosticFile
	failStop   func(context.Context) error

	mu           sync.RWMutex
	health       Health
	diagnosticMu sync.Mutex
	runMu        sync.Mutex
	runDone      chan struct{}
	running      bool
	providerStop providerShutdown
	injectorStop providerShutdown
}

type providerShutdown struct {
	mu        sync.Mutex
	started   bool
	completed bool
	done      chan struct{}
	err       error
}

func NewRuntime(config Config) (*Runtime, error) {
	if config.PipeName == "" {
		return nil, errors.New("helper pipe name is required")
	}
	if config.DiagnosticFile == "" {
		config.DiagnosticFile = defaultDiagnosticPath()
	}
	if err := validateDiagnosticPath(config.DiagnosticFile, config.DiagnosticOverride); err != nil {
		return nil, err
	}
	if config.Provider == nil {
		config.Provider = NewUnavailableCaptureProvider()
	}
	if config.Injector == nil {
		config.Injector = NewUnavailableInjector()
	}
	if config.TrustedServerBinary == "" || config.TrustedServerSHA256 == "" {
		return nil, errors.New("trusted Core binary path and externally pinned SHA-256 are required")
	}
	diagnostic, err := openDiagnosticFile(config.DiagnosticFile, config.DiagnosticOverride, config.DiagnosticServiceSID, config.DiagnosticOwnerSID)
	if err != nil {
		return nil, err
	}
	failStop := config.FailStop
	if failStop == nil {
		failStop = defaultFailStop
	}
	runtime := &Runtime{config: config, provider: config.Provider, injector: config.Injector, diagnostic: diagnostic, failStop: failStop}
	client, err := capturedudp.NewNamedPipeClient(capturedudp.NamedPipeClientConfig{
		Name: config.PipeName, ServerSIDs: config.ServerSIDs,
		MinimumServerIntegrityRID: config.MinimumServerIntegrityRID,
		TrustedServerBinary:       config.TrustedServerBinary, TrustedServerSHA256: config.TrustedServerSHA256,
		OperationTimeout: config.OperationTimeout,
		ReconnectMin:     config.ReconnectMin, ReconnectMax: config.ReconnectMax,
	}, runtime.handleDelivery)
	if err != nil {
		_ = diagnostic.Close()
		return nil, err
	}
	runtime.client = client
	runtime.refreshHealth()
	return runtime, nil
}

// ValidateCaptureProviderContract rejects providers that only claim the
// required shape. The helper starts a provider only when every ABI, device,
// IOCTL, MTU, capability, and cleanup field is an exact match.
func ValidateCaptureProviderContract(provider CaptureProvider) error {
	if provider == nil {
		return fmt.Errorf("%w: provider is nil", ErrInvalidCaptureContract)
	}
	actual := provider.Contract()
	if err := actual.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCaptureContract, err)
	}
	expected := RequiredWFPDriverContract()
	if actual.Version != expected.Version || actual.ABIVersion != expected.ABIVersion || actual.ContractID != expected.ContractID ||
		actual.DevicePath != expected.DevicePath || actual.CaptureIOCTL != expected.CaptureIOCTL || actual.InjectIOCTL != expected.InjectIOCTL ||
		actual.GetCapabilitiesIOCTL != expected.GetCapabilitiesIOCTL || actual.CancelIOCTL != expected.CancelIOCTL || actual.MaxMTU != expected.MaxMTU ||
		actual.MaxMessageSize != expected.MaxMessageSize || actual.SupportsCancel != expected.SupportsCancel || actual.DynamicSession != expected.DynamicSession ||
		actual.StopCleansDynamicState != expected.StopCleansDynamicState || actual.Capabilities != expected.Capabilities {
		return fmt.Errorf("%w: provider contract differs from required contract", ErrInvalidCaptureContract)
	}
	return nil
}

func (runtime *Runtime) Run(ctx context.Context) (result error) {
	runtime.runMu.Lock()
	if runtime.running {
		runtime.runMu.Unlock()
		return errors.New("helper runtime is already running")
	}
	runtime.running = true
	runtime.runDone = make(chan struct{})
	runtime.runMu.Unlock()
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), runtime.providerStopDeadline(context.Background()))
		providerErr := runtime.stopProviderWithContext(cleanupContext)
		injectorErr := runtime.closeInjectorWithContext(cleanupContext)
		cleanupCancel()
		if result == nil && (providerErr != nil || injectorErr != nil) {
			result = errors.Join(providerErr, injectorErr)
		}
		runtime.refreshHealth()
		_ = runtime.writeDiagnostic()
		runtime.runMu.Lock()
		runtime.running = false
		close(runtime.runDone)
		runtime.runMu.Unlock()
		_ = runtime.closeDiagnostic()
	}()
	runtime.setLifecycle("starting", "")
	if err := ValidateCaptureProviderContract(runtime.provider); err != nil {
		runtime.setLifecycle("failed", err.Error())
		_ = runtime.writeDiagnostic()
		return err
	}
	runtime.setLifecycle("running", "")
	runtime.refreshHealth()
	monitorDone := make(chan struct{})
	go runtime.monitorDiagnostic(ctx, monitorDone)
	defer close(monitorDone)
	if err := runtime.writeDiagnostic(); err != nil {
		return err
	}
	// A provider is intentionally not started when it is unavailable. This
	// prevents a helper skeleton from ever claiming or manufacturing capture.
	if health := runtime.provider.Health(); health.Status == "ready" && health.Verified {
		if err := runtime.provider.Start(ctx, CaptureCallbacks{
			OnDatagram: runtime.handleCapture,
			OnFlowEnd:  runtime.handleFlowEnd,
		}); err != nil {
			runtime.setLifecycle("failed", err.Error())
			return err
		}
	}
	err := runtime.client.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		runtime.setLifecycle("failed", err.Error())
	}
	runtime.refreshHealth()
	_ = runtime.writeDiagnostic()
	return err
}

func (runtime *Runtime) Close() error {
	return runtime.Shutdown(context.Background())
}

// Shutdown closes the client and waits for Run to finish provider and
// injector cleanup. Service callers should pass a bounded context.
func (runtime *Runtime) Shutdown(ctx context.Context) error {
	if runtime.client != nil {
		_ = runtime.client.Close()
	}
	providerErr := runtime.stopProviderWithContext(ctx)
	runtime.runMu.Lock()
	runDone := runtime.runDone
	running := runtime.running
	runtime.runMu.Unlock()
	if running && runDone != nil {
		select {
		case <-runDone:
		case <-ctx.Done():
			runtime.setLifecycle("stop_timeout", ctx.Err().Error())
			diagnosticErr := runtime.writeDiagnostic()
			injectorErr := runtime.closeInjectorWithContext(ctx)
			if providerErr != nil || injectorErr != nil {
				runtime.setLifecycle("failed", errors.Join(providerErr, injectorErr).Error())
			}
			cleanupDiagnosticErr := runtime.writeDiagnostic()
			return errors.Join(ErrRuntimeStopTimeout, ctx.Err(), diagnosticErr, providerErr, injectorErr, cleanupDiagnosticErr)
		}
	} else {
		injectorErr := runtime.closeInjectorWithContext(ctx)
		if providerErr != nil || injectorErr != nil {
			return errors.Join(providerErr, injectorErr)
		}
		_ = runtime.closeDiagnostic()
	}
	if providerErr != nil {
		return providerErr
	}
	if injectorErr := runtime.injectorStopError(); injectorErr != nil {
		return injectorErr
	}
	runtime.setLifecycle("stopped", "")
	_ = runtime.writeDiagnostic()
	return nil
}

func (runtime *Runtime) Health() Health {
	runtime.refreshHealth()
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.health
}

func (runtime *Runtime) Client() capturedudp.NamedPipeClient { return runtime.client }

func (runtime *Runtime) refreshHealth() {
	providerHealth := runtime.provider.Health()
	pipeHealth := runtime.clientHealth()
	tokenSecurity := currentTokenSecurity()
	status, reason := "not_ready", providerHealth.Reason
	if providerHealth.Status == "ready" && providerHealth.Verified && pipeHealth.Connected && pipeHealth.Authenticated {
		status, reason = "ready", "capture provider and authenticated Core pipe are ready"
	}
	runtime.mu.RLock()
	lifecycle := runtime.health.Lifecycle
	lastError := runtime.health.LastError
	stopTimedOut := runtime.health.StopTimedOut
	runtime.mu.RUnlock()
	if lifecycle == "" {
		lifecycle = "created"
	}
	if lifecycle != "failed" && lifecycle != "stop_timeout" {
		lastError = pipeHealth.LastError
	}
	runtime.mu.Lock()
	runtime.health = Health{
		Status: status, Reason: reason, CaptureProvider: providerHealth.Status,
		CaptureCapabilities: providerHealth.Capabilities, PipeConnected: pipeHealth.Connected,
		Authenticated: pipeHealth.Authenticated, Stage: pipeHealth.Stage, Attempt: pipeHealth.Attempt,
		Reconnects: pipeHealth.Reconnects, WFPContractVersion: WFPDriverContractVersion,
		ServiceSIDPresent: tokenSecurity.ServiceSIDPresent, RestrictedSIDCount: tokenSecurity.RestrictedSIDCount,
		PID: os.Getpid(), UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ProviderCleanup: runtime.health.ProviderCleanup,
	}
	runtime.health.Lifecycle = lifecycle
	runtime.health.LastError = lastError
	runtime.health.StopTimedOut = stopTimedOut
	runtime.mu.Unlock()
}

func (runtime *Runtime) setLifecycle(lifecycle, lastError string) {
	runtime.mu.Lock()
	runtime.health.Lifecycle = lifecycle
	runtime.health.LastError = lastError
	runtime.health.StopTimedOut = lifecycle == "stop_timeout"
	runtime.mu.Unlock()
}

func (runtime *Runtime) stopProviderWithContext(ctx context.Context) error {
	done := runtime.startProviderStop(ctx)
	select {
	case <-done:
		return runtime.providerStopError()
	case <-ctx.Done():
		return errors.Join(ErrRuntimeStopTimeout, ctx.Err())
	}
}

func (runtime *Runtime) startProviderStop(ctx context.Context) <-chan struct{} {
	runtime.providerStop.mu.Lock()
	if runtime.providerStop.started {
		done := runtime.providerStop.done
		runtime.providerStop.mu.Unlock()
		return done
	}
	runtime.providerStop.started = true
	runtime.providerStop.done = make(chan struct{})
	done := runtime.providerStop.done
	timeout := runtime.providerStopDeadline(ctx)
	runtime.providerStop.mu.Unlock()
	go func() {
		runtime.mu.Lock()
		runtime.health.ProviderCleanup = "stopping"
		runtime.mu.Unlock()
		stopContext, stopCancel := context.WithTimeout(context.Background(), timeout)
		defer stopCancel()
		stopResult := make(chan error, 1)
		go func() { stopResult <- runtime.provider.Stop(stopContext) }()
		select {
		case err := <-stopResult:
			runtime.finishProviderStop(err)
		case <-stopContext.Done():
			runtime.setLifecycle("stop_timeout", stopContext.Err().Error())
			diagnosticErr := runtime.writeDiagnostic()
			failStopContext, failStopCancel := context.WithTimeout(context.Background(), time.Second)
			failStopErr := runtime.failStop(failStopContext)
			failStopCancel()
			runtime.finishProviderStop(errors.Join(ErrRuntimeStopTimeout, stopContext.Err(), diagnosticErr, failStopErr))
		}
	}()
	return done
}

func (runtime *Runtime) providerStopDeadline(ctx context.Context) time.Duration {
	timeout := runtime.config.OperationTimeout
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Nanosecond
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	return timeout
}

func (runtime *Runtime) finishProviderStop(err error) {
	runtime.providerStop.mu.Lock()
	if runtime.providerStop.completed || runtime.providerStop.done == nil {
		runtime.providerStop.mu.Unlock()
		return
	}
	runtime.providerStop.completed = true
	runtime.providerStop.err = err
	close(runtime.providerStop.done)
	runtime.providerStop.mu.Unlock()
	runtime.mu.Lock()
	if err == nil {
		runtime.health.ProviderCleanup = "confirmed"
	} else {
		runtime.health.ProviderCleanup = "failed"
	}
	runtime.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrRuntimeStopTimeout) {
			runtime.setLifecycle("stop_timeout", err.Error())
		} else {
			runtime.setLifecycle("failed", err.Error())
		}
	}
}

func (runtime *Runtime) providerStopError() error {
	runtime.providerStop.mu.Lock()
	defer runtime.providerStop.mu.Unlock()
	return runtime.providerStop.err
}

func (runtime *Runtime) closeInjector() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = runtime.closeInjectorWithContext(ctx)
}

func (runtime *Runtime) closeInjectorWithContext(ctx context.Context) error {
	done := runtime.startInjectorClose(ctx)
	select {
	case <-done:
		return runtime.injectorStopError()
	case <-ctx.Done():
		return errors.Join(ErrRuntimeStopTimeout, ctx.Err())
	}
}

func (runtime *Runtime) startInjectorClose(ctx context.Context) <-chan struct{} {
	runtime.injectorStop.mu.Lock()
	if runtime.injectorStop.started {
		done := runtime.injectorStop.done
		runtime.injectorStop.mu.Unlock()
		return done
	}
	runtime.injectorStop.started = true
	runtime.injectorStop.done = make(chan struct{})
	done := runtime.injectorStop.done
	timeout := runtime.providerStopDeadline(ctx)
	runtime.injectorStop.mu.Unlock()
	go func() {
		closeContext, closeCancel := context.WithTimeout(context.Background(), timeout)
		defer closeCancel()
		closeResult := make(chan error, 1)
		go func() { closeResult <- runtime.injector.Close(closeContext) }()
		select {
		case err := <-closeResult:
			runtime.finishInjectorClose(err)
		case <-closeContext.Done():
			runtime.finishInjectorClose(errors.Join(ErrRuntimeStopTimeout, closeContext.Err()))
		}
	}()
	return done
}

func (runtime *Runtime) finishInjectorClose(err error) {
	runtime.injectorStop.mu.Lock()
	if runtime.injectorStop.completed || runtime.injectorStop.done == nil {
		runtime.injectorStop.mu.Unlock()
		return
	}
	runtime.injectorStop.completed = true
	runtime.injectorStop.err = err
	close(runtime.injectorStop.done)
	runtime.injectorStop.mu.Unlock()
	if err != nil {
		runtime.setLifecycle("failed", err.Error())
	}
}

func (runtime *Runtime) injectorStopError() error {
	runtime.injectorStop.mu.Lock()
	defer runtime.injectorStop.mu.Unlock()
	return runtime.injectorStop.err
}

func (runtime *Runtime) handleCapture(ctx context.Context, captured CapturedDatagram) error {
	defer clear(captured.Payload)
	return runtime.client.SendDatagram(ctx, capturedudp.Datagram{
		FlowID: captured.Identity.FlowID, Generation: captured.Identity.Generation,
		LeaseNonce: captured.Identity.LeaseNonce, Sequence: captured.Sequence,
		Payload: append([]byte(nil), captured.Payload...),
	})
}

func (runtime *Runtime) handleFlowEnd(ctx context.Context, identity FlowIdentity, _ error) error {
	return runtime.injector.CloseFlow(ctx, identity)
}

func (runtime *Runtime) clientHealth() capturedudp.NamedPipeClientHealth {
	if runtime.client == nil {
		return capturedudp.NamedPipeClientHealth{}
	}
	return runtime.client.Health()
}

func (runtime *Runtime) handleDelivery(ctx context.Context, delivery capturedudp.NamedPipeDelivery) error {
	defer clear(delivery.Payload)
	return runtime.injector.Inject(ctx, Delivery{
		Identity: FlowIdentity{FlowID: delivery.FlowID, Generation: delivery.Generation, LeaseNonce: delivery.LeaseNonce},
		Payload:  append([]byte(nil), delivery.Payload...),
	})
}

func (runtime *Runtime) writeDiagnostic() error {
	if runtime.diagnostic == nil {
		return nil
	}
	runtime.diagnosticMu.Lock()
	defer runtime.diagnosticMu.Unlock()
	data, err := json.MarshalIndent(runtime.Health(), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal helper health: %w", err)
	}
	return runtime.diagnostic.Write(data)
}

func (runtime *Runtime) closeDiagnostic() error {
	runtime.diagnosticMu.Lock()
	defer runtime.diagnosticMu.Unlock()
	if runtime.diagnostic == nil {
		return nil
	}
	err := runtime.diagnostic.Close()
	runtime.diagnostic = nil
	return err
}

func (runtime *Runtime) monitorDiagnostic(ctx context.Context, done <-chan struct{}) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			runtime.refreshHealth()
			_ = runtime.writeDiagnostic()
		}
	}
}
