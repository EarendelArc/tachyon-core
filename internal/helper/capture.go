// Package helper contains the privileged Windows helper boundary.
package helper

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	WFPDriverContractVersion = "tachyon-wfp-callout-v2"
	WFPDriverABIVersion      = wfpDeviceABIMajor
	WFPMaxMessageSize        = uint32(wfpMaxMessageSize)
)

var ErrCaptureUnavailable = errors.New("WFP receive injection is not implemented; capture provider is not ready")

type CaptureCapabilities struct {
	FlowCapture       bool
	DatagramCapture   bool
	ProcessIdentity   bool
	PerFlowMTU        bool
	Cancelable        bool
	MultipathMetadata bool
}

type FlowIdentity struct {
	FlowID                     [16]byte
	Generation                 uint64
	LeaseNonce                 [16]byte
	PID                        uint32
	ProcessStartKey            uint64
	AppIDHash                  [32]byte
	UserSecurityDescriptorHash [32]byte
	Direction                  uint8
	ProcessStart               time.Time
	Local                      netip.AddrPort
	Remote                     netip.AddrPort
	Protocol                   uint8
}

type CapturedDatagram struct {
	Identity FlowIdentity
	Sequence uint64
	Payload  []byte
}

type Delivery struct {
	Identity FlowIdentity
	Sequence uint64
	Payload  []byte
}

type CaptureCallbacks struct {
	OnDatagram func(context.Context, CapturedDatagram) error
	OnFlowEnd  func(context.Context, FlowIdentity, error) error
}

type ProviderHealth struct {
	Status       string
	Reason       string
	Verified     bool
	Capabilities CaptureCapabilities
	MTU          uint32
}

type CaptureProvider interface {
	Contract() WFPDriverContract
	Start(context.Context, CaptureCallbacks) error
	Stop(context.Context) error
	Health() ProviderHealth
}

type PolicyCaptureProvider interface {
	CaptureProvider
	ActivatePolicy(context.Context, WFPPolicy) error
	DisablePolicy(context.Context) error
}

type Injector interface {
	Inject(context.Context, Delivery) error
	CloseFlow(context.Context, FlowIdentity) error
	Close(context.Context) error
}

// WFPDriverContract is composed exclusively from constants generated from
// tachyon_wfp_abi.h. It intentionally has no receive-injection capability.
type WFPDriverContract struct {
	Version                string
	ABIVersion             uint16
	DevicePath             string
	NegotiateIOCTL         uint32
	SetPolicyIOCTL         uint32
	DisablePolicyIOCTL     uint32
	DequeueIOCTL           uint32
	VerdictIOCTL           uint32
	StatisticsIOCTL        uint32
	MaxMTU                 uint32
	MaxMessageSize         uint32
	SupportsCancel         bool
	DynamicSession         bool
	StopCleansDynamicState bool
	Capabilities           CaptureCapabilities
}

func (contract WFPDriverContract) Validate() error {
	if contract.Version != WFPDriverContractVersion || contract.ABIVersion != WFPDriverABIVersion {
		return errors.New("WFP contract version mismatch")
	}
	ioctls := []uint32{contract.NegotiateIOCTL, contract.SetPolicyIOCTL, contract.DisablePolicyIOCTL,
		contract.DequeueIOCTL, contract.VerdictIOCTL, contract.StatisticsIOCTL}
	if contract.DevicePath == "" {
		return errors.New("WFP contract device path is empty")
	}
	for index, ioctl := range ioctls {
		if ioctl == 0 {
			return errors.New("WFP contract has an empty IOCTL")
		}
		for _, other := range ioctls[index+1:] {
			if ioctl == other {
				return errors.New("WFP contract has duplicate IOCTLs")
			}
		}
	}
	if contract.MaxMTU < 576 || contract.MaxMTU > 65535 || contract.MaxMessageSize != WFPMaxMessageSize {
		return errors.New("WFP contract has invalid bounds")
	}
	capabilities := contract.Capabilities
	if !contract.SupportsCancel || !contract.DynamicSession || !contract.StopCleansDynamicState ||
		!capabilities.FlowCapture || !capabilities.DatagramCapture || !capabilities.ProcessIdentity ||
		!capabilities.PerFlowMTU || !capabilities.Cancelable {
		return errors.New("WFP contract lacks required capture-only capabilities")
	}
	return nil
}

func RequiredWFPDriverContract() WFPDriverContract {
	return WFPDriverContract{
		Version: WFPDriverContractVersion, ABIVersion: WFPDriverABIVersion, DevicePath: `\\.\TachyonWFP`,
		NegotiateIOCTL: ioctlWFPNegotiate, SetPolicyIOCTL: ioctlWFPSetPolicy,
		DisablePolicyIOCTL: ioctlWFPDisablePolicy, DequeueIOCTL: ioctlWFPDequeue,
		VerdictIOCTL: ioctlWFPVerdict, StatisticsIOCTL: ioctlWFPStatistics,
		MaxMTU: 1500, MaxMessageSize: WFPMaxMessageSize, SupportsCancel: true,
		DynamicSession: true, StopCleansDynamicState: true,
		Capabilities: CaptureCapabilities{FlowCapture: true, DatagramCapture: true, ProcessIdentity: true,
			PerFlowMTU: true, Cancelable: true},
	}
}

func ValidateCaptureProviderContract(provider CaptureProvider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}
	actual := provider.Contract()
	if err := actual.Validate(); err != nil {
		return err
	}
	if actual != RequiredWFPDriverContract() {
		return errors.New("provider contract differs from canonical generated WFP contract")
	}
	return nil
}

type unavailableProvider struct{}

func NewUnavailableCaptureProvider() CaptureProvider    { return unavailableProvider{} }
func (unavailableProvider) Contract() WFPDriverContract { return RequiredWFPDriverContract() }
func (unavailableProvider) Start(context.Context, CaptureCallbacks) error {
	return ErrCaptureUnavailable
}
func (unavailableProvider) Stop(context.Context) error { return nil }
func (unavailableProvider) Health() ProviderHealth {
	return ProviderHealth{Status: "not_ready", Reason: ErrCaptureUnavailable.Error()}
}

type unavailableInjector struct{}

func NewUnavailableInjector() Injector                                    { return unavailableInjector{} }
func (unavailableInjector) Inject(context.Context, Delivery) error        { return ErrCaptureUnavailable }
func (unavailableInjector) CloseFlow(context.Context, FlowIdentity) error { return nil }
func (unavailableInjector) Close(context.Context) error                   { return nil }
