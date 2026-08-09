package helper

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureWFPTransport struct {
	mu       sync.Mutex
	reads    chan []byte
	verdicts [][]byte
	policy   []byte
	closed   bool
}

func newFixtureWFPTransport() *fixtureWFPTransport {
	return &fixtureWFPTransport{reads: make(chan []byte, 8)}
}

func (fixture *fixtureWFPTransport) Negotiate(_ context.Context, request []byte) ([]byte, error) {
	header, err := parseWFPHeader(request, wfpMessageNegotiateRequest)
	if err != nil {
		return nil, err
	}
	response := make([]byte, wfpNegotiateResponseSize)
	putWFPHeader(response, wfpMessageNegotiateResponse, uint32(len(response)), header.RequestID)
	for index := range 16 {
		response[32+index] = byte(index + 1)
	}
	binary.LittleEndian.PutUint64(response[48:56], wfpRequiredCapabilities)
	binary.LittleEndian.PutUint32(response[56:60], WFPMaxMessageSize)
	binary.LittleEndian.PutUint32(response[60:64], wfpDefaultQueueCapacity)
	binary.LittleEndian.PutUint32(response[64:68], wfpDefaultVerdictMS)
	binary.LittleEndian.PutUint32(response[68:72], 1)
	for index := range 32 {
		response[72+index] = byte(255 - index)
	}
	return response, nil
}

func (fixture *fixtureWFPTransport) SetPolicy(_ context.Context, input []byte) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.policy = append([]byte(nil), input...)
	return nil
}
func (fixture *fixtureWFPTransport) DisablePolicy(context.Context, []byte) error { return nil }
func (fixture *fixtureWFPTransport) ReadCapture(ctx context.Context, output []byte) (int, error) {
	select {
	case wire, ok := <-fixture.reads:
		if !ok {
			return 0, context.Canceled
		}
		copy(output, wire)
		clear(wire)
		return len(wire), nil
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

func fixtureCapture(generation, sequence, requestID uint64, nonce [16]byte) []byte {
	wire := make([]byte, wfpCaptureHeaderSize+4)
	putWFPHeader(wire, wfpMessageCapture, uint32(len(wire)), requestID)
	for index := range 16 {
		wire[32+index] = byte(index + 1)
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

func fixturePolicy() WFPPolicy {
	var nonce [16]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	return WFPPolicy{Generation: 7, LeaseNonce: nonce, Processes: []WFPProcessPolicy{{ProcessID: 1234, MatchPID: true}}}
}

func TestWFPDeviceProviderNegotiatesActivatesAndTunnelsInOrder(t *testing.T) {
	transport := newFixtureWFPTransport()
	provider, err := newWFPDeviceProvider(transport)
	if err != nil {
		t.Fatal(err)
	}
	if health := provider.Health(); health.Status != "ready" || !health.Verified {
		t.Fatalf("health = %+v", health)
	}
	policy := fixturePolicy()
	if err := provider.ActivatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	called := make(chan CapturedDatagram, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- provider.Start(ctx, CaptureCallbacks{OnDatagram: func(_ context.Context, datagram CapturedDatagram) error { called <- datagram; return nil }})
	}()
	transport.reads <- fixtureCapture(policy.Generation, 1, 100, policy.LeaseNonce)
	select {
	case datagram := <-called:
		if string(datagram.Payload) != "game" || datagram.Identity.PID != 1234 || datagram.Sequence != 1 {
			t.Fatalf("capture metadata mismatch")
		}
		clear(datagram.Payload)
	case <-time.After(time.Second):
		t.Fatal("capture callback timed out")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.verdicts) != 1 || binary.LittleEndian.Uint32(transport.verdicts[0][80:84]) != wfpVerdictTunnel {
		t.Fatalf("missing tunnel verdict")
	}
}

func TestWFPDeviceProviderRejectsStaleLeaseAndReplayFailOpen(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate   func([]byte)
		expected error
	}{
		"stale-lease":  {func(wire []byte) { wire[56] ^= 0xff }, ErrWFPDeviceLease},
		"out-of-order": {func(wire []byte) { binary.LittleEndian.PutUint64(wire[72:80], 2) }, ErrWFPDeviceReplay},
	} {
		t.Run(name, func(t *testing.T) {
			transport := newFixtureWFPTransport()
			provider, err := newWFPDeviceProvider(transport)
			if err != nil {
				t.Fatal(err)
			}
			policy := fixturePolicy()
			if err := provider.ActivatePolicy(context.Background(), policy); err != nil {
				t.Fatal(err)
			}
			wire := fixtureCapture(policy.Generation, 1, 101, policy.LeaseNonce)
			testCase.mutate(wire)
			transport.reads <- wire
			err = provider.Start(context.Background(), CaptureCallbacks{})
			if !errors.Is(err, testCase.expected) {
				t.Fatalf("error = %v", err)
			}
			transport.mu.Lock()
			defer transport.mu.Unlock()
			if len(transport.verdicts) != 1 || binary.LittleEndian.Uint32(transport.verdicts[0][80:84]) != wfpVerdictPermitDirect {
				t.Fatal("invalid frame was not failed open")
			}
		})
	}
}

func TestWFPDeviceCodecRejectsMalformedFrames(t *testing.T) {
	policy := fixturePolicy()
	valid := fixtureCapture(policy.Generation, 1, 9, policy.LeaseNonce)
	for name, mutate := range map[string]func([]byte){
		"magic":     func(wire []byte) { wire[0] ^= 1 },
		"major":     func(wire []byte) { wire[6]++ },
		"size":      func(wire []byte) { wire[16]++ },
		"reserved":  func(wire []byte) { wire[220] = 1 },
		"payload":   func(wire []byte) { wire[216]++ },
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

func TestWFPDriverHeaderMirrorsGoABIAndRestrictsDeviceACL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("repository path fixture uses Windows worktree layout")
	}
	headerPath := filepath.Join("..", "..", "drivers", "windows", "wfp", "include", "tachyon_wfp_abi.h")
	header, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(header)
	for _, required := range []string{
		"#define TACHYON_WFP_ABI_MAJOR 2u", "#define TACHYON_WFP_CAPTURE_HEADER_SIZE 224u",
		"IOCTL_TACHYON_WFP_NEGOTIATE", "TACHYON_WFP_CAP_FAIL_OPEN_TIMEOUT",
		"static_assert(offsetof(TACHYON_WFP_CAPTURE_RECORD, payload) == TACHYON_WFP_CAPTURE_HEADER_SIZE",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("driver ABI missing %q", required)
		}
	}
	driverHeader, err := os.ReadFile(filepath.Join("..", "..", "drivers", "windows", "wfp", "src", "tachyon_wfp.h"))
	if err != nil {
		t.Fatal(err)
	}
	acl := string(driverHeader)
	if !strings.Contains(acl, "(A;;GA;;;SY)") || !strings.Contains(acl, "S-1-5-80-1356003462-1404488631-2219046169-124586702-828318184") || strings.Contains(acl, ";;;BA)") || strings.Contains(acl, ";;;WD)") {
		t.Fatal("device ACL is not limited to LocalSystem and TachyonHelper Service SID")
	}
}
