// Package helper contains the privileged-helper boundary. It deliberately
// exposes contracts without shipping a WFP callout driver or a fake capture
// implementation.
package helper

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"
)

const WFPDriverContractVersion = "tachyon-wfp-callout-v1"

const (
	WFPDriverABIVersion uint16 = 1
	WFPDriverContractID uint32 = 0x54414348
	WFPMaxMessageSize   uint32 = 64 << 10
	WFPKindHandshake    uint16 = 1
	WFPKindFlow         uint16 = 2
	WFPKindDatagram     uint16 = 3
	WFPKindDelivery     uint16 = 4
	WFPKindCancel       uint16 = 5
	WFPFlagFlowCapture  uint64 = 1 << iota
	WFPFlagDatagramCapture
	WFPFlagProcessIdentity
	WFPFlagKernelInjection
	WFPFlagCancelable
)

var ErrCaptureUnavailable = errors.New("no verified Windows capture provider is installed")

type CaptureCapabilities struct {
	FlowCapture       bool
	DatagramCapture   bool
	ProcessIdentity   bool
	PerFlowMTU        bool
	Cancelable        bool
	KernelInjection   bool
	MultipathMetadata bool
}

type FlowIdentity struct {
	FlowID       [16]byte
	Generation   uint64
	LeaseNonce   [16]byte
	PID          uint32
	ProcessStart time.Time
	Local        netip.AddrPort
	Remote       netip.AddrPort
	Protocol     uint8
}

type CapturedDatagram struct {
	Identity FlowIdentity
	Sequence uint64
	Payload  []byte
}

type Delivery struct {
	Identity FlowIdentity
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

// CaptureProvider is the only source of captured packets. A production WFP
// implementation must prove its driver contract before returning ready.
type CaptureProvider interface {
	Contract() WFPDriverContract
	Start(context.Context, CaptureCallbacks) error
	Stop(context.Context) error
	Health() ProviderHealth
}

// Injector is the only path for a validated delivery to return to the
// original application. Implementations must enforce flow identity and MTU.
type Injector interface {
	Inject(context.Context, Delivery) error
	CloseFlow(context.Context, FlowIdentity) error
	Close(context.Context) error
}

type WFPDriverContract struct {
	Version              string
	ABIVersion           uint16
	ContractID           uint32
	DevicePath           string
	CaptureIOCTL         uint32
	InjectIOCTL          uint32
	GetCapabilitiesIOCTL uint32
	CancelIOCTL          uint32
	MaxMTU               uint32
	MaxMessageSize       uint32
	SupportsCancel       bool
	Capabilities         CaptureCapabilities
}

// WFPABIHeader is the fixed little-endian prefix of every proposed driver
// message. Size includes the header and any trailing payload.
type WFPABIHeader struct {
	Size      uint32
	Version   uint16
	Kind      uint16
	RequestID uint64
}

type WFPDriverHandshake struct {
	Header       WFPABIHeader
	ContractID   uint32
	Capabilities uint64
	MaxMTU       uint32
	Reserved     uint32
}

type WFPFlowIdentityABI struct {
	Header        WFPABIHeader
	FlowID        [16]byte
	Generation    uint64
	PID           uint32
	Protocol      uint8
	AddressFamily uint8
	Reserved      uint16
	LocalIP       [16]byte
	RemoteIP      [16]byte
	LocalPort     uint16
	RemotePort    uint16
}

type WFPDatagramABI struct {
	Header      WFPABIHeader
	FlowID      [16]byte
	Generation  uint64
	Sequence    uint64
	PayloadSize uint32
	Reserved    uint32
	Payload     [0]byte
}

func (contract WFPDriverContract) Validate() error {
	if contract.Version != WFPDriverContractVersion || contract.ABIVersion != WFPDriverABIVersion || contract.ContractID != WFPDriverContractID {
		return fmt.Errorf("WFP contract version or ID mismatch")
	}
	if contract.DevicePath == "" || contract.CaptureIOCTL == 0 || contract.InjectIOCTL == 0 || contract.GetCapabilitiesIOCTL == 0 || contract.CancelIOCTL == 0 {
		return fmt.Errorf("WFP contract has incomplete device or IOCTL definitions")
	}
	ioctls := []uint32{contract.CaptureIOCTL, contract.InjectIOCTL, contract.GetCapabilitiesIOCTL, contract.CancelIOCTL}
	for index, ioctl := range ioctls {
		for _, other := range ioctls[index+1:] {
			if ioctl == other {
				return fmt.Errorf("WFP contract has duplicate IOCTL definitions")
			}
		}
	}
	if contract.MaxMTU < 576 || contract.MaxMTU > 65535 || contract.MaxMessageSize < uint32(unsafe.Sizeof(WFPDatagramABI{})) || contract.MaxMessageSize > WFPMaxMessageSize {
		return fmt.Errorf("WFP contract has invalid message or MTU bounds")
	}
	if !contract.SupportsCancel || !contract.Capabilities.Cancelable || !contract.Capabilities.FlowCapture || !contract.Capabilities.DatagramCapture || !contract.Capabilities.ProcessIdentity || !contract.Capabilities.PerFlowMTU || !contract.Capabilities.KernelInjection {
		return fmt.Errorf("WFP contract lacks required capabilities")
	}
	return nil
}

func (handshake WFPDriverHandshake) Validate(maxMessageSize uint32) error {
	if handshake.Header.Kind != WFPKindHandshake || handshake.Header.Version != WFPDriverABIVersion || handshake.Header.Size != uint32(unsafe.Sizeof(handshake)) || handshake.Header.Size > maxMessageSize {
		return fmt.Errorf("invalid WFP handshake header")
	}
	requiredCapabilities := WFPFlagFlowCapture | WFPFlagDatagramCapture | WFPFlagProcessIdentity | WFPFlagKernelInjection | WFPFlagCancelable
	if handshake.ContractID != WFPDriverContractID || handshake.Capabilities&requiredCapabilities != requiredCapabilities || handshake.MaxMTU < 576 || handshake.MaxMTU > 65535 {
		return fmt.Errorf("invalid WFP handshake contract")
	}
	return nil
}

func ValidateWFPMessageHeader(header WFPABIHeader, expectedKind uint16, maxMessageSize uint32) error {
	minimum := uint32(unsafe.Sizeof(WFPABIHeader{}))
	if header.Size < minimum || header.Size > maxMessageSize || header.Version != WFPDriverABIVersion || header.Kind != expectedKind || header.RequestID == 0 {
		return fmt.Errorf("invalid WFP message header")
	}
	return nil
}

func RequiredWFPDriverContract() WFPDriverContract {
	return WFPDriverContract{
		Version:              WFPDriverContractVersion,
		ABIVersion:           WFPDriverABIVersion,
		ContractID:           WFPDriverContractID,
		DevicePath:           `\\.\TachyonWFP`,
		CaptureIOCTL:         0x00222000,
		InjectIOCTL:          0x00222004,
		GetCapabilitiesIOCTL: 0x00222008,
		CancelIOCTL:          0x0022200c,
		MaxMTU:               1500,
		MaxMessageSize:       WFPMaxMessageSize,
		SupportsCancel:       true,
		Capabilities: CaptureCapabilities{
			FlowCapture: true, DatagramCapture: true, ProcessIdentity: true,
			PerFlowMTU: true, Cancelable: true, KernelInjection: true,
		},
	}
}

type unavailableProvider struct{}

func NewUnavailableCaptureProvider() CaptureProvider { return unavailableProvider{} }

func (unavailableProvider) Contract() WFPDriverContract { return RequiredWFPDriverContract() }

func (unavailableProvider) Start(context.Context, CaptureCallbacks) error {
	return ErrCaptureUnavailable
}

func (unavailableProvider) Stop(context.Context) error { return nil }

func (unavailableProvider) Health() ProviderHealth {
	return ProviderHealth{
		Status: "not_ready", Reason: ErrCaptureUnavailable.Error(), Verified: false,
		Capabilities: CaptureCapabilities{}, MTU: 0,
	}
}

type unavailableInjector struct{}

func NewUnavailableInjector() Injector { return unavailableInjector{} }

func (unavailableInjector) Inject(context.Context, Delivery) error { return ErrCaptureUnavailable }

func (unavailableInjector) CloseFlow(context.Context, FlowIdentity) error { return nil }

func (unavailableInjector) Close(context.Context) error { return nil }
