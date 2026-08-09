package helper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type fixtureWFPTransport struct {
	mu           sync.Mutex
	reads        chan []byte
	verdicts     [][]byte
	policy       []byte
	disable      []byte
	disableCalls int
	closed       bool
}

func newFixtureWFPTransport() *fixtureWFPTransport {
	return &fixtureWFPTransport{reads: make(chan []byte, 8)}
}

func (fixture *fixtureWFPTransport) Negotiate(_ context.Context, request []byte) ([]byte, error) {
	header, err := parseWFPHeader(request, wfpMessageNegotiateRequest)
	if err != nil || [16]byte(request[32:48]) != wfpHelperBuildID {
		return nil, ErrWFPDeviceProtocol
	}
	response := make([]byte, wfpNegotiateResponseSize)
	putWFPHeader(response, wfpMessageNegotiateResponse, uint32(len(response)), header.RequestID)
	copy(response[32:48], wfpDriverBuildID[:])
	binary.LittleEndian.PutUint64(response[48:56], wfpRequiredCapabilities)
	binary.LittleEndian.PutUint32(response[56:60], WFPMaxMessageSize)
	binary.LittleEndian.PutUint32(response[60:64], wfpDefaultQueueCapacity)
	binary.LittleEndian.PutUint32(response[64:68], wfpDefaultVerdictMS)
	binary.LittleEndian.PutUint32(response[68:72], 1)
	copy(response[72:104], wfpHelperServiceSIDHash[:])
	return response, nil
}

func (fixture *fixtureWFPTransport) SetPolicy(_ context.Context, input []byte) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.policy = append([]byte(nil), input...)
	return nil
}
func (fixture *fixtureWFPTransport) DisablePolicy(_ context.Context, input []byte) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.disableCalls++
	fixture.disable = append([]byte(nil), input...)
	return nil
}
func (fixture *fixtureWFPTransport) ReadCapture(ctx context.Context, output []byte) (int, error) {
	select {
	case wire, ok := <-fixture.reads:
		if !ok {
			return 0, context.Canceled
		}
		size := len(wire)
		copy(output, wire)
		clear(wire)
		return size, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (fixture *fixtureWFPTransport) WriteVerdict(_ context.Context, input []byte) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.verdicts = append(fixture.verdicts, append([]byte(nil), input...))
	return nil
}
func (fixture *fixtureWFPTransport) Cancel() error { return nil }
func (fixture *fixtureWFPTransport) Close() error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if !fixture.closed {
		close(fixture.reads)
		fixture.closed = true
	}
	return nil
}

func fixtureCaptureForFlow(generation, sequence, requestID uint64, nonce [16]byte, flowByte byte) []byte {
	wire := make([]byte, wfpCaptureHeaderSize+4)
	putWFPHeader(wire, wfpMessageCapture, uint32(len(wire)), requestID)
	for index := range 16 {
		wire[32+index] = flowByte + byte(index)
	}
	binary.LittleEndian.PutUint64(wire[48:56], generation)
	copy(wire[56:72], nonce[:])
	binary.LittleEndian.PutUint64(wire[72:80], sequence)
	binary.LittleEndian.PutUint64(wire[80:88], 1234)
	binary.LittleEndian.PutUint64(wire[88:96], 5678)
	for index := range 32 {
		wire[96+index], wire[128+index] = byte(index+1), byte(index+33)
	}
	binary.LittleEndian.PutUint16(wire[160:162], 2)
	wire[162], wire[163] = 1, 17
	copy(wire[180:184], []byte{127, 0, 0, 1})
	copy(wire[196:200], []byte{1, 1, 1, 1})
	binary.LittleEndian.PutUint16(wire[212:214], 32000)
	binary.LittleEndian.PutUint16(wire[214:216], 27015)
	binary.LittleEndian.PutUint32(wire[216:220], 4)
	copy(wire[224:], "game")
	return wire
}

func fixtureCapture(generation, sequence, requestID uint64, nonce [16]byte) []byte {
	return fixtureCaptureForFlow(generation, sequence, requestID, nonce, 1)
}

func fixturePolicy() WFPPolicy {
	var nonce [16]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	return WFPPolicy{Generation: 7, LeaseNonce: nonce, Processes: []WFPProcessPolicy{{ProcessID: 1234, MatchPID: true}}}
}

func newFixtureProvider(t *testing.T) (*WFPDeviceProvider, *fixtureWFPTransport) {
	t.Helper()
	transport := newFixtureWFPTransport()
	provider, err := newWFPDeviceProvider(transport)
	if err != nil {
		t.Fatal(err)
	}
	return provider, transport
}

func TestWFPDeviceProviderVerifiesCaptureOnlyABIAndStaysNotReady(t *testing.T) {
	provider, transport := newFixtureProvider(t)
	health := provider.Health()
	if health.Status != "not_ready" || !health.Verified || !strings.Contains(health.Reason, "receive injection is unavailable") {
		t.Fatalf("health = %+v", health)
	}
	if err := provider.ActivatePolicy(context.Background(), fixturePolicy()); !errors.Is(err, ErrCaptureUnavailable) {
		t.Fatalf("activate policy error = %v", err)
	}
	if err := provider.Inject(context.Background(), Delivery{}); !errors.Is(err, ErrCaptureUnavailable) {
		t.Fatalf("inject error = %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.policy) != 0 {
		t.Fatal("not-ready provider wrote a kernel policy")
	}
}

func TestWFPSequenceGapIsIsolatedToOneFlow(t *testing.T) {
	provider, transport := newFixtureProvider(t)
	policy := fixturePolicy()
	provider.mu.Lock()
	provider.policy = policy
	ended := 0
	provider.callbacks.OnDatagram = func(context.Context, CapturedDatagram) error { return nil }
	provider.callbacks.OnFlowEnd = func(context.Context, FlowIdentity, error) error { ended++; return nil }
	provider.mu.Unlock()

	flowA1, err := parseWFPCapture(fixtureCaptureForFlow(policy.Generation, 1, 10, policy.LeaseNonce, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.acceptCapture(context.Background(), flowA1); err != nil {
		t.Fatal(err)
	}
	clear(flowA1.Payload)
	flowAGap, _ := parseWFPCapture(fixtureCaptureForFlow(policy.Generation, 3, 11, policy.LeaseNonce, 1))
	if err := provider.acceptCapture(context.Background(), flowAGap); !errors.Is(err, ErrWFPDeviceReplay) {
		t.Fatalf("gap error = %v", err)
	}
	clear(flowAGap.Payload)
	flowB1, _ := parseWFPCapture(fixtureCaptureForFlow(policy.Generation, 1, 12, policy.LeaseNonce, 64))
	if err := provider.acceptCapture(context.Background(), flowB1); err != nil {
		t.Fatalf("independent flow failed: %v", err)
	}
	clear(flowB1.Payload)
	if ended != 1 {
		t.Fatalf("flow end callbacks = %d", ended)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.verdicts) != 3 || binary.LittleEndian.Uint32(transport.verdicts[1][80:84]) != wfpVerdictPermitDirect ||
		binary.LittleEndian.Uint32(transport.verdicts[2][80:84]) != wfpVerdictTunnel {
		t.Fatal("sequence gap affected another flow or did not fail open")
	}
}

func TestWFPStaleLeaseIsolatedAndCloseFlowClearsSequence(t *testing.T) {
	provider, _ := newFixtureProvider(t)
	policy := fixturePolicy()
	provider.mu.Lock()
	provider.policy = policy
	provider.callbacks.OnDatagram = func(context.Context, CapturedDatagram) error { return nil }
	provider.mu.Unlock()
	stale := fixtureCaptureForFlow(policy.Generation, 1, 20, policy.LeaseNonce, 1)
	stale[56] ^= 0xff
	frame, _ := parseWFPCapture(stale)
	if err := provider.acceptCapture(context.Background(), frame); !errors.Is(err, ErrWFPDeviceLease) {
		t.Fatalf("lease error = %v", err)
	}
	clear(frame.Payload)
	valid, _ := parseWFPCapture(fixtureCaptureForFlow(policy.Generation, 1, 21, policy.LeaseNonce, 64))
	if err := provider.acceptCapture(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	if err := provider.CloseFlow(context.Background(), FlowIdentity{FlowID: valid.FlowID}); err != nil {
		t.Fatal(err)
	}
	provider.mu.RLock()
	_, exists := provider.sequences[valid.FlowID]
	provider.mu.RUnlock()
	clear(valid.Payload)
	if exists {
		t.Fatal("CloseFlow retained sequence state")
	}
}

func TestWFPDisablePolicyClearsLeaseAndSequenceAfterKernelAck(t *testing.T) {
	provider, transport := newFixtureProvider(t)
	policy := fixturePolicy()
	flowID := [16]byte{1}
	provider.mu.Lock()
	provider.policy = policy
	provider.sequences[flowID] = 9
	provider.delivery[flowID] = 4
	provider.mu.Unlock()
	if err := provider.DisablePolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	provider.mu.RLock()
	active, sequenceCount, deliveryCount := provider.policy.Generation, len(provider.sequences), len(provider.delivery)
	provider.mu.RUnlock()
	transport.mu.Lock()
	disable := append([]byte(nil), transport.disable...)
	calls := transport.disableCalls
	transport.mu.Unlock()
	defer clear(disable)
	if active != 0 || sequenceCount != 0 || deliveryCount != 0 || calls != 1 {
		t.Fatal("disable did not clear acknowledged provider state")
	}
	if len(disable) != wfpDisablePolicySize || binary.LittleEndian.Uint64(disable[32:40]) != policy.Generation ||
		[16]byte(disable[40:56]) != policy.LeaseNonce {
		t.Fatal("disable frame does not carry the active generation and lease")
	}
}

func TestCanonicalServiceSIDUsesTrustedUTF8Hash(t *testing.T) {
	if actual := sha256.Sum256([]byte(wfpHelperServiceSID)); actual != wfpHelperServiceSIDHash {
		t.Fatalf("canonical Service SID hash = %x, generated = %x", actual, wfpHelperServiceSIDHash)
	}
}

func TestWFPDeviceCodecRejectsUnknownFlagsAndMalformedFrames(t *testing.T) {
	policy := fixturePolicy()
	valid := fixtureCapture(policy.Generation, 1, 9, policy.LeaseNonce)
	for name, mutate := range map[string]func([]byte){
		"magic": func(wire []byte) { wire[0] ^= 1 }, "flags": func(wire []byte) { wire[12] = 1 },
		"major": func(wire []byte) { wire[6]++ }, "size": func(wire []byte) { wire[16]++ },
		"reserved": func(wire []byte) { wire[220] = 1 }, "payload": func(wire []byte) { wire[216]++ },
		"injection": func(wire []byte) { wire[164] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			mutate(wire)
			frame, err := parseWFPCapture(wire)
			clear(frame.Payload)
			if err == nil {
				t.Fatal("malformed frame accepted")
			}
		})
	}
}

func TestWFPDriverHeaderIsCanonicalAndRestrictsDeviceACL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("repository path fixture uses Windows worktree layout")
	}
	headerPath := filepath.Join("..", "..", "drivers", "windows", "wfp", "include", "tachyon_wfp_abi.h")
	header, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(header)
	for _, required := range []string{"_Static_assert(offsetof(TACHYON_WFP_CAPTURE_RECORD, payload)",
		"TACHYON_WFP_HELPER_SERVICE_SID_ASCII", "TACHYON_WFP_DRIVER_BUILD_ID_INIT", "IOCTL_TACHYON_WFP_NEGOTIATE"} {
		if !strings.Contains(text, required) {
			t.Fatalf("driver ABI missing %q", required)
		}
	}
	if strings.Contains(text, "CAP_INJECT_RECEIVE") || strings.Contains(text, "VerdictInjectToApplication") {
		t.Fatal("canonical C ABI advertises unimplemented receive injection")
	}
	driverHeader, err := os.ReadFile(filepath.Join("..", "..", "drivers", "windows", "wfp", "src", "tachyon_wfp.h"))
	if err != nil {
		t.Fatal(err)
	}
	acl := string(driverHeader)
	if !strings.Contains(acl, "(A;;GA;;;SY)") || !strings.Contains(acl, "TACHYON_WFP_HELPER_SERVICE_SID_WIDE") ||
		strings.Contains(acl, ";;;BA)") || strings.Contains(acl, ";;;WD)") {
		t.Fatal("device ACL is not limited to LocalSystem and canonical Helper Service SID")
	}
	deviceSource, err := os.ReadFile(filepath.Join("..", "..", "drivers", "windows", "wfp", "src", "device.c"))
	if err != nil {
		t.Fatal(err)
	}
	cleanup := string(deviceSource)
	closeIndex, clearIndex := strings.Index(cleanup, "InterlockedExchange(&context->client_open, 0)"), strings.Index(cleanup, "TgClearPolicy(context)")
	if closeIndex < 0 || clearIndex < 0 || closeIndex > clearIndex {
		t.Fatal("file cleanup does not stop capture before clearing policy")
	}
}
