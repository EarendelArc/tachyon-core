package helper

import (
	"context"
	"errors"
	"testing"
	"unsafe"
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
	header := WFPABIHeader{Size: uint32(unsafe.Sizeof(WFPABIHeader{})), Version: WFPDriverABIVersion, Kind: WFPKindDatagram, RequestID: 1}
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
	handshake := WFPDriverHandshake{
		Header:     WFPABIHeader{Size: uint32(unsafe.Sizeof(WFPDriverHandshake{})), Version: WFPDriverABIVersion, Kind: WFPKindHandshake, RequestID: 1},
		ContractID: WFPDriverContractID, Capabilities: WFPFlagFlowCapture | WFPFlagDatagramCapture | WFPFlagProcessIdentity | WFPFlagKernelInjection | WFPFlagCancelable,
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
