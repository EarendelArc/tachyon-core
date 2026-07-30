// Package helper contains the privileged-helper boundary. It deliberately
// exposes contracts without shipping a WFP callout driver or a fake capture
// implementation.
package helper

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
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

const (
	WFPABIHeaderWireSize      = 16
	WFPHandshakeWireSize      = 36
	WFPFlowIdentityWireSize   = 84
	WFPDatagramHeaderWireSize = 56
	WFPRequiredCapabilityMask = WFPFlagFlowCapture | WFPFlagDatagramCapture | WFPFlagProcessIdentity | WFPFlagKernelInjection | WFPFlagCancelable
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
	Version                string
	ABIVersion             uint16
	ContractID             uint32
	DevicePath             string
	CaptureIOCTL           uint32
	InjectIOCTL            uint32
	GetCapabilitiesIOCTL   uint32
	CancelIOCTL            uint32
	MaxMTU                 uint32
	MaxMessageSize         uint32
	SupportsCancel         bool
	DynamicSession         bool
	StopCleansDynamicState bool
	Capabilities           CaptureCapabilities
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

type WFPDatagramMessage struct {
	RequestID  uint64
	FlowID     [16]byte
	Generation uint64
	Sequence   uint64
	Payload    []byte
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
	if contract.MaxMTU < 576 || contract.MaxMTU > 65535 || contract.MaxMessageSize < WFPDatagramHeaderWireSize || contract.MaxMessageSize > WFPMaxMessageSize {
		return fmt.Errorf("WFP contract has invalid message or MTU bounds")
	}
	if !contract.SupportsCancel || !contract.DynamicSession || !contract.StopCleansDynamicState || !contract.Capabilities.Cancelable || !contract.Capabilities.FlowCapture || !contract.Capabilities.DatagramCapture || !contract.Capabilities.ProcessIdentity || !contract.Capabilities.PerFlowMTU || !contract.Capabilities.KernelInjection {
		return fmt.Errorf("WFP contract lacks required capabilities")
	}
	return nil
}

func (handshake WFPDriverHandshake) Validate(maxMessageSize uint32) error {
	if handshake.Header.Kind != WFPKindHandshake || handshake.Header.Version != WFPDriverABIVersion || handshake.Header.Size != WFPHandshakeWireSize || handshake.Header.Size > maxMessageSize || handshake.Header.RequestID == 0 {
		return fmt.Errorf("invalid WFP handshake header")
	}
	if handshake.ContractID != WFPDriverContractID || handshake.Capabilities&WFPRequiredCapabilityMask != WFPRequiredCapabilityMask || handshake.MaxMTU < 576 || handshake.MaxMTU > 65535 {
		return fmt.Errorf("invalid WFP handshake contract")
	}
	return nil
}

func ValidateWFPMessageHeader(header WFPABIHeader, expectedKind uint16, maxMessageSize uint32) error {
	if maxMessageSize < WFPABIHeaderWireSize || maxMessageSize > WFPMaxMessageSize ||
		header.Size < WFPABIHeaderWireSize || header.Size > maxMessageSize ||
		header.Version != WFPDriverABIVersion || header.Kind != expectedKind || header.RequestID == 0 {
		return fmt.Errorf("invalid WFP message header")
	}
	return nil
}

func MarshalWFPDriverHandshake(handshake WFPDriverHandshake, maxMessageSize uint32) ([]byte, error) {
	handshake.Header.Size = WFPHandshakeWireSize
	if err := handshake.Validate(maxMessageSize); err != nil {
		return nil, err
	}
	data := make([]byte, WFPHandshakeWireSize)
	encodeWFPABIHeader(data, handshake.Header)
	binary.LittleEndian.PutUint32(data[16:20], handshake.ContractID)
	binary.LittleEndian.PutUint64(data[20:28], handshake.Capabilities)
	binary.LittleEndian.PutUint32(data[28:32], handshake.MaxMTU)
	binary.LittleEndian.PutUint32(data[32:36], handshake.Reserved)
	return data, nil
}

func UnmarshalWFPDriverHandshake(data []byte, maxMessageSize uint32) (WFPDriverHandshake, error) {
	if len(data) != WFPHandshakeWireSize {
		return WFPDriverHandshake{}, fmt.Errorf("invalid WFP handshake length")
	}
	header, err := decodeWFPABIHeader(data[:WFPABIHeaderWireSize])
	if err != nil {
		return WFPDriverHandshake{}, err
	}
	if err := ValidateWFPMessageHeader(header, WFPKindHandshake, maxMessageSize); err != nil {
		return WFPDriverHandshake{}, err
	}
	if header.Size != WFPHandshakeWireSize {
		return WFPDriverHandshake{}, fmt.Errorf("invalid WFP handshake size")
	}
	handshake := WFPDriverHandshake{Header: header,
		ContractID:   binary.LittleEndian.Uint32(data[16:20]),
		Capabilities: binary.LittleEndian.Uint64(data[20:28]),
		MaxMTU:       binary.LittleEndian.Uint32(data[28:32]),
		Reserved:     binary.LittleEndian.Uint32(data[32:36]),
	}
	return handshake, handshake.Validate(maxMessageSize)
}

func MarshalWFPDatagram(message WFPDatagramMessage, maxMessageSize uint32) ([]byte, error) {
	if message.RequestID == 0 || uint32(WFPDatagramHeaderWireSize+len(message.Payload)) > maxMessageSize || maxMessageSize > WFPMaxMessageSize {
		return nil, fmt.Errorf("invalid WFP datagram length or request ID")
	}
	data := make([]byte, WFPDatagramHeaderWireSize+len(message.Payload))
	encodeWFPABIHeader(data, WFPABIHeader{Size: uint32(len(data)), Version: WFPDriverABIVersion, Kind: WFPKindDatagram, RequestID: message.RequestID})
	copy(data[16:32], message.FlowID[:])
	binary.LittleEndian.PutUint64(data[32:40], message.Generation)
	binary.LittleEndian.PutUint64(data[40:48], message.Sequence)
	binary.LittleEndian.PutUint32(data[48:52], uint32(len(message.Payload)))
	copy(data[WFPDatagramHeaderWireSize:], message.Payload)
	return data, nil
}

func UnmarshalWFPDatagram(data []byte, maxMessageSize uint32) (WFPDatagramMessage, error) {
	if len(data) < WFPDatagramHeaderWireSize || uint32(len(data)) > maxMessageSize {
		return WFPDatagramMessage{}, fmt.Errorf("invalid WFP datagram length")
	}
	header, err := decodeWFPABIHeader(data[:WFPABIHeaderWireSize])
	if err != nil {
		return WFPDatagramMessage{}, err
	}
	if err := ValidateWFPMessageHeader(header, WFPKindDatagram, maxMessageSize); err != nil {
		return WFPDatagramMessage{}, err
	}
	if header.Size != uint32(len(data)) {
		return WFPDatagramMessage{}, fmt.Errorf("invalid WFP datagram header")
	}
	payloadSize := binary.LittleEndian.Uint32(data[48:52])
	if payloadSize != uint32(len(data)-WFPDatagramHeaderWireSize) {
		return WFPDatagramMessage{}, fmt.Errorf("WFP datagram payload size mismatch")
	}
	var flowID [16]byte
	copy(flowID[:], data[16:32])
	return WFPDatagramMessage{RequestID: header.RequestID, FlowID: flowID,
		Generation: binary.LittleEndian.Uint64(data[32:40]),
		Sequence:   binary.LittleEndian.Uint64(data[40:48]),
		Payload:    append([]byte(nil), data[WFPDatagramHeaderWireSize:]...)}, nil
}

func MarshalWFPFlowIdentity(identity WFPFlowIdentityABI, maxMessageSize uint32) ([]byte, error) {
	identity.Header.Size = WFPFlowIdentityWireSize
	if identity.Header.Kind != WFPKindFlow || identity.Header.Version != WFPDriverABIVersion || identity.Header.RequestID == 0 || uint32(WFPFlowIdentityWireSize) > maxMessageSize {
		return nil, fmt.Errorf("invalid WFP flow identity")
	}
	data := make([]byte, WFPFlowIdentityWireSize)
	encodeWFPABIHeader(data, identity.Header)
	copy(data[16:32], identity.FlowID[:])
	binary.LittleEndian.PutUint64(data[32:40], identity.Generation)
	binary.LittleEndian.PutUint32(data[40:44], identity.PID)
	data[44] = identity.Protocol
	data[45] = identity.AddressFamily
	binary.LittleEndian.PutUint16(data[46:48], identity.Reserved)
	copy(data[48:64], identity.LocalIP[:])
	copy(data[64:80], identity.RemoteIP[:])
	binary.LittleEndian.PutUint16(data[80:82], identity.LocalPort)
	binary.LittleEndian.PutUint16(data[82:84], identity.RemotePort)
	return data, nil
}

func UnmarshalWFPFlowIdentity(data []byte, maxMessageSize uint32) (WFPFlowIdentityABI, error) {
	if len(data) != WFPFlowIdentityWireSize || uint32(len(data)) > maxMessageSize {
		return WFPFlowIdentityABI{}, fmt.Errorf("invalid WFP flow identity length")
	}
	header, err := decodeWFPABIHeader(data[:WFPABIHeaderWireSize])
	if err != nil {
		return WFPFlowIdentityABI{}, err
	}
	if err := ValidateWFPMessageHeader(header, WFPKindFlow, maxMessageSize); err != nil {
		return WFPFlowIdentityABI{}, err
	}
	if header.Size != WFPFlowIdentityWireSize {
		return WFPFlowIdentityABI{}, fmt.Errorf("invalid WFP flow identity header")
	}
	identity := WFPFlowIdentityABI{Header: header, Generation: binary.LittleEndian.Uint64(data[32:40]), PID: binary.LittleEndian.Uint32(data[40:44]), Protocol: data[44], AddressFamily: data[45], Reserved: binary.LittleEndian.Uint16(data[46:48]), LocalPort: binary.LittleEndian.Uint16(data[80:82]), RemotePort: binary.LittleEndian.Uint16(data[82:84])}
	copy(identity.FlowID[:], data[16:32])
	copy(identity.LocalIP[:], data[48:64])
	copy(identity.RemoteIP[:], data[64:80])
	return identity, nil
}

func encodeWFPABIHeader(destination []byte, header WFPABIHeader) {
	binary.LittleEndian.PutUint32(destination[0:4], header.Size)
	binary.LittleEndian.PutUint16(destination[4:6], header.Version)
	binary.LittleEndian.PutUint16(destination[6:8], header.Kind)
	binary.LittleEndian.PutUint64(destination[8:16], header.RequestID)
}

func decodeWFPABIHeader(data []byte) (WFPABIHeader, error) {
	if len(data) != WFPABIHeaderWireSize {
		return WFPABIHeader{}, fmt.Errorf("invalid WFP ABI header length")
	}
	return WFPABIHeader{Size: binary.LittleEndian.Uint32(data[0:4]), Version: binary.LittleEndian.Uint16(data[4:6]), Kind: binary.LittleEndian.Uint16(data[6:8]), RequestID: binary.LittleEndian.Uint64(data[8:16])}, nil
}

func RequiredWFPDriverContract() WFPDriverContract {
	return WFPDriverContract{
		Version:                WFPDriverContractVersion,
		ABIVersion:             WFPDriverABIVersion,
		ContractID:             WFPDriverContractID,
		DevicePath:             `\\.\TachyonWFP`,
		CaptureIOCTL:           0x00222000,
		InjectIOCTL:            0x00222004,
		GetCapabilitiesIOCTL:   0x00222008,
		CancelIOCTL:            0x0022200c,
		MaxMTU:                 1500,
		MaxMessageSize:         WFPMaxMessageSize,
		SupportsCancel:         true,
		DynamicSession:         true,
		StopCleansDynamicState: true,
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
