package helper

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type wfpDeviceTransport interface {
	Negotiate(context.Context, []byte) ([]byte, error)
	SetPolicy(context.Context, []byte) error
	DisablePolicy(context.Context, []byte) error
	ReadCapture(context.Context, []byte) (int, error)
	WriteVerdict(context.Context, []byte) error
	Cancel() error
	Close() error
}

type WFPProcessPolicy struct {
	ProcessID    uint64
	ProcessStart uint64
	AppIDHash    [32]byte
	UserSIDHash  [32]byte
	MatchPID     bool
	MatchStart   bool
	MatchAppID   bool
	MatchUserSID bool
}

type WFPPolicy struct {
	Generation uint64
	LeaseNonce [16]byte
	Processes  []WFPProcessPolicy
}

type WFPDeviceProvider struct {
	transport wfpDeviceTransport

	mu         sync.RWMutex
	health     ProviderHealth
	callbacks  CaptureCallbacks
	policy     WFPPolicy
	sequences  map[[16]byte]uint64
	delivery   map[[16]byte]uint64
	running    bool
	closed     bool
	requestID  atomic.Uint64
	loopCancel context.CancelFunc
	loopDone   chan struct{}
}

func newWFPDeviceProvider(transport wfpDeviceTransport) (*WFPDeviceProvider, error) {
	if transport == nil {
		return nil, fmt.Errorf("%w: device transport is nil", ErrCaptureUnavailable)
	}
	provider := &WFPDeviceProvider{transport: transport, sequences: make(map[[16]byte]uint64), delivery: make(map[[16]byte]uint64)}
	provider.requestID.Store(1)
	var helperBuild [16]byte
	if _, err := rand.Read(helperBuild[:]); err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("create WFP helper build nonce: %w", err)
	}
	requestID := provider.nextRequestID()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	wire, err := transport.Negotiate(ctx, marshalWFPNegotiate(requestID, helperBuild))
	cancel()
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("negotiate WFP driver: %w", err)
	}
	response, err := parseWFPNegotiate(wire, requestID)
	clear(wire)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	provider.health = ProviderHealth{
		Status: "ready", Reason: fmt.Sprintf("verified WFP ABI %d.%d build %x", wfpDeviceABIMajor, wfpDeviceABIMinor, response.BuildID),
		Verified: true, MTU: 1500,
		Capabilities: CaptureCapabilities{FlowCapture: true, DatagramCapture: true, ProcessIdentity: true,
			PerFlowMTU: true, Cancelable: true, KernelInjection: true},
	}
	return provider, nil
}

func (provider *WFPDeviceProvider) nextRequestID() uint64 {
	for {
		value := provider.requestID.Add(1)
		if value != 0 {
			return value
		}
	}
}

func (provider *WFPDeviceProvider) Contract() WFPDriverContract { return RequiredWFPDriverContract() }

func (provider *WFPDeviceProvider) Health() ProviderHealth {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	return provider.health
}

func (provider *WFPDeviceProvider) ActivatePolicy(ctx context.Context, policy WFPPolicy) error {
	entries := make([]wfpPolicyEntry, len(policy.Processes))
	for index, process := range policy.Processes {
		entry := wfpPolicyEntry{ProcessID: process.ProcessID, ProcessStart: process.ProcessStart, AppIDHash: process.AppIDHash, UserSIDHash: process.UserSIDHash}
		if process.MatchPID {
			entry.MatchFlags |= 1 << 0
		}
		if process.MatchStart {
			entry.MatchFlags |= 1 << 1
		}
		if process.MatchAppID {
			entry.MatchFlags |= 1 << 2
		}
		if process.MatchUserSID {
			entry.MatchFlags |= 1 << 3
		}
		entries[index] = entry
	}
	wire, err := marshalWFPPolicy(provider.nextRequestID(), policy.Generation, policy.LeaseNonce, entries)
	if err != nil {
		return err
	}
	defer clear(wire)
	if err := provider.transport.SetPolicy(ctx, wire); err != nil {
		return fmt.Errorf("activate WFP policy: %w", err)
	}
	provider.mu.Lock()
	provider.policy = WFPPolicy{Generation: policy.Generation, LeaseNonce: policy.LeaseNonce, Processes: append([]WFPProcessPolicy(nil), policy.Processes...)}
	clear(provider.sequences)
	clear(provider.delivery)
	provider.mu.Unlock()
	return nil
}

func (provider *WFPDeviceProvider) Start(ctx context.Context, callbacks CaptureCallbacks) error {
	provider.mu.Lock()
	if provider.closed {
		provider.mu.Unlock()
		return ErrCaptureUnavailable
	}
	if provider.running {
		provider.mu.Unlock()
		return errors.New("WFP device provider is already running")
	}
	if !provider.health.Verified || provider.health.Status != "ready" {
		provider.mu.Unlock()
		return ErrCaptureUnavailable
	}
	loopCtx, cancel := context.WithCancel(ctx)
	provider.callbacks = callbacks
	provider.running = true
	provider.loopCancel = cancel
	provider.loopDone = make(chan struct{})
	done := provider.loopDone
	provider.mu.Unlock()
	defer func() {
		provider.mu.Lock()
		provider.running = false
		provider.loopCancel = nil
		close(done)
		provider.mu.Unlock()
	}()
	buffer := make([]byte, WFPMaxMessageSize)
	defer clear(buffer)
	for {
		size, err := provider.transport.ReadCapture(loopCtx, buffer)
		if err != nil {
			if loopCtx.Err() != nil {
				return nil
			}
			provider.markFailed(err)
			return err
		}
		frame, err := parseWFPCapture(buffer[:size])
		if err == nil {
			err = provider.acceptCapture(loopCtx, frame)
		}
		clear(buffer[:size])
		clear(frame.Payload)
		if err != nil {
			provider.markFailed(err)
			return err
		}
	}
}

func (provider *WFPDeviceProvider) acceptCapture(ctx context.Context, frame wfpCaptureFrame) error {
	provider.mu.Lock()
	if frame.Generation != provider.policy.Generation || frame.LeaseNonce != provider.policy.LeaseNonce {
		provider.mu.Unlock()
		_ = provider.writeVerdict(ctx, frame, wfpVerdictPermitDirect, nil)
		return ErrWFPDeviceLease
	}
	last := provider.sequences[frame.FlowID]
	if frame.Sequence != last+1 {
		provider.mu.Unlock()
		_ = provider.writeVerdict(ctx, frame, wfpVerdictPermitDirect, nil)
		return ErrWFPDeviceReplay
	}
	provider.sequences[frame.FlowID] = frame.Sequence
	callbacks := provider.callbacks
	provider.mu.Unlock()
	local, remote, err := wfpFrameEndpoints(frame)
	if err != nil {
		_ = provider.writeVerdict(ctx, frame, wfpVerdictPermitDirect, nil)
		return err
	}
	identity := FlowIdentity{
		FlowID: frame.FlowID, Generation: frame.Generation, LeaseNonce: frame.LeaseNonce,
		PID: uint32(frame.ProcessID), ProcessStartKey: frame.ProcessStart, AppIDHash: frame.AppIDHash,
		UserSIDHash: frame.UserSIDHash, Direction: frame.Direction, Local: local, Remote: remote, Protocol: frame.Protocol,
	}
	if callbacks.OnDatagram == nil {
		return provider.writeVerdict(ctx, frame, wfpVerdictPermitDirect, nil)
	}
	err = callbacks.OnDatagram(ctx, CapturedDatagram{Identity: identity, Sequence: frame.Sequence, Payload: append([]byte(nil), frame.Payload...)})
	if err != nil {
		_ = provider.writeVerdict(ctx, frame, wfpVerdictPermitDirect, nil)
		return err
	}
	return provider.writeVerdict(ctx, frame, wfpVerdictTunnel, nil)
}

func (provider *WFPDeviceProvider) writeVerdict(ctx context.Context, frame wfpCaptureFrame, action uint32, payload []byte) error {
	wire, err := marshalWFPVerdict(frame, action, payload)
	if err != nil {
		return err
	}
	defer clear(wire)
	return provider.transport.WriteVerdict(ctx, wire)
}

func (provider *WFPDeviceProvider) Inject(ctx context.Context, delivery Delivery) error {
	provider.mu.Lock()
	if delivery.Identity.Generation != provider.policy.Generation || delivery.Identity.LeaseNonce != provider.policy.LeaseNonce {
		provider.mu.Unlock()
		return ErrWFPDeviceLease
	}
	sequence := provider.delivery[delivery.Identity.FlowID] + 1
	if delivery.Sequence != 0 {
		sequence = delivery.Sequence
	}
	if sequence <= provider.delivery[delivery.Identity.FlowID] {
		provider.mu.Unlock()
		return ErrWFPDeviceReplay
	}
	provider.delivery[delivery.Identity.FlowID] = sequence
	provider.mu.Unlock()
	frame := wfpCaptureFrame{RequestID: provider.nextRequestID(), FlowID: delivery.Identity.FlowID,
		Generation: delivery.Identity.Generation, LeaseNonce: delivery.Identity.LeaseNonce, Sequence: sequence}
	return provider.writeVerdict(ctx, frame, wfpVerdictInjectToApplication, delivery.Payload)
}

func (provider *WFPDeviceProvider) CloseFlow(context.Context, FlowIdentity) error { return nil }

func (provider *WFPDeviceProvider) Stop(ctx context.Context) error {
	provider.mu.RLock()
	cancel, done := provider.loopCancel, provider.loopDone
	provider.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
	_ = provider.transport.Cancel()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (provider *WFPDeviceProvider) Close(ctx context.Context) error {
	if err := provider.Stop(ctx); err != nil {
		return err
	}
	provider.mu.Lock()
	if provider.closed {
		provider.mu.Unlock()
		return nil
	}
	provider.closed = true
	provider.mu.Unlock()
	return provider.transport.Close()
}

func (provider *WFPDeviceProvider) markFailed(err error) {
	provider.mu.Lock()
	provider.health.Status, provider.health.Verified = "not_ready", false
	provider.health.Reason = err.Error()
	provider.mu.Unlock()
}
