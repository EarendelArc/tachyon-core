package helper

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailableCaptureProviderNeverReportsReadyOrProducesPackets(t *testing.T) {
	provider := NewUnavailableCaptureProvider()
	if health := provider.Health(); health.Status != "not_ready" || health.Verified || health.Capabilities != (CaptureCapabilities{}) {
		t.Fatalf("unavailable provider health = %+v", health)
	}
	if err := provider.Start(context.Background(), CaptureCallbacks{}); !errors.Is(err, ErrCaptureUnavailable) {
		t.Fatalf("start error = %v", err)
	}
	if err := NewUnavailableInjector().Inject(context.Background(), Delivery{}); !errors.Is(err, ErrCaptureUnavailable) {
		t.Fatalf("inject error = %v", err)
	}
}

func TestRequiredWFPDriverContractIsExplicitlyVersioned(t *testing.T) {
	contract := RequiredWFPDriverContract()
	if err := contract.Validate(); err != nil {
		t.Fatal(err)
	}
	if contract.Version != WFPDriverContractVersion || contract.DevicePath == "" || !contract.SupportsCancel {
		t.Fatalf("invalid WFP contract = %+v", contract)
	}
	if !contract.Capabilities.FlowCapture || !contract.Capabilities.KernelInjection {
		t.Fatalf("contract capabilities = %+v", contract.Capabilities)
	}
}

func TestWFPABIRejectsWrongVersionKindAndLengths(t *testing.T) {
	contract := RequiredWFPDriverContract()
	header := WFPABIHeader{Size: WFPABIHeaderWireSize, Version: WFPDriverABIVersion, Kind: WFPKindDatagram, RequestID: 1}
	if err := ValidateWFPMessageHeader(header, WFPKindDatagram, contract.MaxMessageSize); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*WFPABIHeader){
		func(value *WFPABIHeader) { value.Version++ },
		func(value *WFPABIHeader) { value.Kind = WFPKindFlow },
		func(value *WFPABIHeader) { value.Size = contract.MaxMessageSize + 1 },
		func(value *WFPABIHeader) { value.RequestID = 0 },
	} {
		copy := header
		mutate(&copy)
		if err := ValidateWFPMessageHeader(copy, WFPKindDatagram, contract.MaxMessageSize); err == nil {
			t.Fatalf("mutated header unexpectedly accepted: %+v", copy)
		}
	}
	if err := ValidateWFPMessageHeader(header, WFPKindDatagram, WFPMaxMessageSize+1); err == nil {
		t.Fatal("oversized decode limit unexpectedly accepted")
	}
	handshake := WFPDriverHandshake{
		Header:     WFPABIHeader{Size: WFPHandshakeWireSize, Version: WFPDriverABIVersion, Kind: WFPKindHandshake, RequestID: 1},
		ContractID: WFPDriverContractID, Capabilities: WFPRequiredCapabilityMask,
		MaxMTU: contract.MaxMTU,
	}
	if err := handshake.Validate(contract.MaxMessageSize); err != nil {
		t.Fatal(err)
	}
	handshake.Header.Size--
	if err := handshake.Validate(contract.MaxMessageSize); err == nil {
		t.Fatal("truncated handshake unexpectedly accepted")
	}
}

func TestWFPWireCodecIsLittleEndianAndChecksPayloadLength(t *testing.T) {
	handshake := WFPDriverHandshake{
		Header:     WFPABIHeader{Version: WFPDriverABIVersion, Kind: WFPKindHandshake, RequestID: 0x0102030405060708},
		ContractID: WFPDriverContractID, Capabilities: WFPRequiredCapabilityMask, MaxMTU: 1500,
	}
	wire, err := MarshalWFPDriverHandshake(handshake, WFPMaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	if wire[0] != WFPHandshakeWireSize || wire[8] != 0x08 || wire[15] != 0x01 {
		t.Fatalf("handshake is not little-endian wire data: %x", wire)
	}
	decoded, err := UnmarshalWFPDriverHandshake(wire, WFPMaxMessageSize)
	if err != nil || decoded.Header.RequestID != handshake.Header.RequestID || decoded.ContractID != handshake.ContractID {
		t.Fatalf("handshake round trip = %+v, error=%v", decoded, err)
	}
	message := WFPDatagramMessage{RequestID: 7, Generation: 9, Sequence: 11, Payload: []byte("payload")}
	message.FlowID[0] = 0xaa
	datagram, err := MarshalWFPDatagram(message, WFPMaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	decodedDatagram, err := UnmarshalWFPDatagram(datagram, WFPMaxMessageSize)
	if err != nil || string(decodedDatagram.Payload) != "payload" || decodedDatagram.FlowID[0] != 0xaa {
		t.Fatalf("datagram round trip = %+v, error=%v", decodedDatagram, err)
	}
	datagram[48]++
	if _, err := UnmarshalWFPDatagram(datagram, WFPMaxMessageSize); err == nil {
		t.Fatal("payload size mismatch unexpectedly accepted")
	}
	flow := WFPFlowIdentityABI{Header: WFPABIHeader{Version: WFPDriverABIVersion, Kind: WFPKindFlow, RequestID: 13}, Generation: 17, PID: 19, Protocol: 17, AddressFamily: 2, LocalPort: 1000, RemotePort: 2000}
	flow.FlowID[0] = 0xbb
	flow.LocalIP[0] = 127
	flowWire, err := MarshalWFPFlowIdentity(flow, WFPMaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	decodedFlow, err := UnmarshalWFPFlowIdentity(flowWire, WFPMaxMessageSize)
	if err != nil || decodedFlow.FlowID[0] != 0xbb || decodedFlow.LocalPort != 1000 || decodedFlow.RemotePort != 2000 {
		t.Fatalf("flow round trip = %+v, error=%v", decodedFlow, err)
	}
}

func TestWFPUnmarshalRejectsEveryInvalidHeaderField(t *testing.T) {
	datagram, err := MarshalWFPDatagram(WFPDatagramMessage{RequestID: 1, Payload: []byte("x")}, WFPMaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := MarshalWFPFlowIdentity(WFPFlowIdentityABI{Header: WFPABIHeader{Version: WFPDriverABIVersion, Kind: WFPKindFlow, RequestID: 1}}, WFPMaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte){
		"version": func(wire []byte) { wire[4]++ },
		"kind":    func(wire []byte) { wire[6]++ },
		"size":    func(wire []byte) { wire[0]++ },
		"request": func(wire []byte) { clear(wire[8:16]) },
	} {
		t.Run("datagram/"+name, func(t *testing.T) {
			wire := append([]byte(nil), datagram...)
			mutate(wire)
			if _, err := UnmarshalWFPDatagram(wire, WFPMaxMessageSize); err == nil {
				t.Fatal("invalid datagram header accepted")
			}
		})
		t.Run("flow/"+name, func(t *testing.T) {
			wire := append([]byte(nil), flow...)
			mutate(wire)
			if _, err := UnmarshalWFPFlowIdentity(wire, WFPMaxMessageSize); err == nil {
				t.Fatal("invalid flow header accepted")
			}
		})
	}
}

func TestWFPContractRequiresCleanupAndExactIOCTLs(t *testing.T) {
	contract := RequiredWFPDriverContract()
	contract.DynamicSession = false
	if err := contract.Validate(); err == nil {
		t.Fatal("dynamic session contract without cleanup unexpectedly accepted")
	}
	contract = RequiredWFPDriverContract()
	contract.InjectIOCTL = contract.CaptureIOCTL
	if err := contract.Validate(); err == nil {
		t.Fatal("duplicate IOCTL contract unexpectedly accepted")
	}
}
