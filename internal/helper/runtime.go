package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/capturedudp"
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
	DiagnosticFile            string
	DiagnosticOverride        bool
	Provider                  CaptureProvider
	Injector                  Injector
}

type Health struct {
	Status              string              `json:"status"`
	Reason              string              `json:"reason"`
	CaptureProvider     string              `json:"capture_provider"`
	CaptureCapabilities CaptureCapabilities `json:"capture_capabilities"`
	PipeConnected       bool                `json:"pipe_connected"`
	Authenticated       bool                `json:"authenticated"`
	WFPContractVersion  string              `json:"wfp_contract_version"`
	ServiceSIDPresent   bool                `json:"service_sid_present"`
	RestrictedSIDCount  int                 `json:"restricted_sid_count"`
	PID                 int                 `json:"pid"`
	UpdatedAt           string              `json:"updated_at"`
	Lifecycle           string              `json:"lifecycle"`
	LastError           string              `json:"last_error,omitempty"`
	StopTimedOut        bool                `json:"stop_timed_out"`
}

type Runtime struct {
	config   Config
	provider CaptureProvider
	injector Injector
	client   capturedudp.NamedPipeClient

	mu                sync.RWMutex
	health            Health
	diagnosticMu      sync.Mutex
	runMu             sync.Mutex
	runDone           chan struct{}
	running           bool
	providerStopOnce  sync.Once
	providerStopErr   error
	injectorCloseOnce sync.Once
	injectorCloseErr  error
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
	if config.TrustedServerBinary == "" {
		path, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve trusted Core binary: %w", err)
		}
		config.TrustedServerBinary = path
	}
	if config.TrustedServerSHA256 == "" {
		hash, err := hashFile(config.TrustedServerBinary)
		if err != nil {
			return nil, fmt.Errorf("hash trusted Core binary: %w", err)
		}
		config.TrustedServerSHA256 = hash
	}
	runtime := &Runtime{config: config, provider: config.Provider, injector: config.Injector}
	client, err := capturedudp.NewNamedPipeClient(capturedudp.NamedPipeClientConfig{
		Name: config.PipeName, ServerSIDs: config.ServerSIDs,
		MinimumServerIntegrityRID: config.MinimumServerIntegrityRID,
		TrustedServerBinary:       config.TrustedServerBinary, TrustedServerSHA256: config.TrustedServerSHA256,
		OperationTimeout: config.OperationTimeout,
		ReconnectMin:     config.ReconnectMin, ReconnectMax: config.ReconnectMax,
	}, runtime.handleDelivery)
	if err != nil {
		return nil, err
	}
	runtime.client = client
	runtime.refreshHealth()
	return runtime, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	runtime.runMu.Lock()
	if runtime.running {
		runtime.runMu.Unlock()
		return errors.New("helper runtime is already running")
	}
	runtime.running = true
	runtime.runDone = make(chan struct{})
	runtime.runMu.Unlock()
	defer func() {
		runtime.stopProvider()
		runtime.closeInjector()
		runtime.refreshHealth()
		_ = runtime.writeDiagnostic()
		runtime.runMu.Lock()
		runtime.running = false
		close(runtime.runDone)
		runtime.runMu.Unlock()
	}()
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
	runtime.runMu.Lock()
	runDone := runtime.runDone
	running := runtime.running
	runtime.runMu.Unlock()
	if running && runDone != nil {
		select {
		case <-runDone:
		case <-ctx.Done():
			runtime.setLifecycle("stop_timeout", ctx.Err().Error())
			_ = runtime.writeDiagnostic()
			return errors.Join(errors.New("helper runtime shutdown timed out"), ctx.Err())
		}
	} else {
		runtime.stopProvider()
		runtime.closeInjector()
	}
	if runtime.providerStopErr != nil {
		return runtime.providerStopErr
	}
	if runtime.injectorCloseErr != nil {
		return runtime.injectorCloseErr
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
	runtime.mu.Lock()
	runtime.health = Health{
		Status: status, Reason: reason, CaptureProvider: providerHealth.Status,
		CaptureCapabilities: providerHealth.Capabilities, PipeConnected: pipeHealth.Connected,
		Authenticated: pipeHealth.Authenticated, WFPContractVersion: WFPDriverContractVersion,
		ServiceSIDPresent: tokenSecurity.ServiceSIDPresent, RestrictedSIDCount: tokenSecurity.RestrictedSIDCount,
		PID: os.Getpid(), UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
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

func (runtime *Runtime) stopProvider() {
	runtime.providerStopOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		runtime.providerStopErr = runtime.provider.Stop(ctx)
		if runtime.providerStopErr != nil {
			runtime.setLifecycle("failed", runtime.providerStopErr.Error())
		}
	})
}

func (runtime *Runtime) closeInjector() {
	runtime.injectorCloseOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		runtime.injectorCloseErr = runtime.injector.Close(ctx)
		if runtime.injectorCloseErr != nil {
			runtime.setLifecycle("failed", runtime.injectorCloseErr.Error())
		}
	})
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
	if runtime.config.DiagnosticFile == "" {
		return nil
	}
	runtime.diagnosticMu.Lock()
	defer runtime.diagnosticMu.Unlock()
	data, err := json.MarshalIndent(runtime.Health(), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal helper health: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(runtime.config.DiagnosticFile), 0o700); err != nil {
		return fmt.Errorf("create helper diagnostic directory: %w", err)
	}
	if err := secureDiagnosticPath(filepath.Dir(runtime.config.DiagnosticFile)); err != nil {
		return err
	}
	temporary := runtime.config.DiagnosticFile + ".tmp"
	if err := validateDiagnosticPath(temporary, runtime.config.DiagnosticOverride); err != nil {
		return err
	}
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("write helper health: %w", err)
	}
	if err := secureDiagnosticPath(temporary); err != nil {
		return err
	}
	return os.Rename(temporary, runtime.config.DiagnosticFile)
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

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
