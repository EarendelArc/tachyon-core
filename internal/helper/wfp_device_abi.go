package helper

//go:generate go run ./cmd/wfpabigen ../../drivers/windows/wfp/include/tachyon_wfp_abi.h wfp_abi_generated.go

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrWFPDeviceProtocol = errors.New("WFP device protocol violation")
	ErrWFPDeviceReplay   = errors.New("WFP device frame is replayed or out of order")
	ErrWFPDeviceLease    = errors.New("WFP device frame has a stale generation or lease")
)

type wfpDeviceHeader struct {
	Kind      uint16
	Flags     uint32
	TotalSize uint32
	RequestID uint64
}

type wfpNegotiateResponse struct {
	BuildID        [16]byte
	Capabilities   uint64
	MaxMessageSize uint32
	QueueCapacity  uint32
	VerdictMS      uint32
	FailPolicy     uint32
	ServiceSIDHash [32]byte
}

type wfpPolicyEntry struct {
	ProcessID                  uint64
	ProcessStart               uint64
	AppIDHash                  [32]byte
	UserSecurityDescriptorHash [32]byte
	MatchFlags                 uint32
}

type wfpCaptureFrame struct {
	RequestID                  uint64
	FlowID                     [16]byte
	Generation                 uint64
	LeaseNonce                 [16]byte
	Sequence                   uint64
	ProcessID                  uint64
	ProcessStart               uint64
	AppIDHash                  [32]byte
	UserSecurityDescriptorHash [32]byte
	AddressFamily              uint16
	Direction                  uint8
	Protocol                   uint8
	InjectionState             uint32
	CompartmentID              uint32
	InterfaceIndex             uint32
	SubInterface               uint32
	LocalAddress               [16]byte
	RemoteAddress              [16]byte
	LocalPort                  uint16
	RemotePort                 uint16
	Payload                    []byte
}

func putWFPHeader(dst []byte, kind uint16, size uint32, requestID uint64) {
	binary.LittleEndian.PutUint32(dst[0:4], wfpDeviceMagic)
	binary.LittleEndian.PutUint16(dst[4:6], wfpDeviceHeaderSize)
	binary.LittleEndian.PutUint16(dst[6:8], wfpDeviceABIMajor)
	binary.LittleEndian.PutUint16(dst[8:10], wfpDeviceABIMinor)
	binary.LittleEndian.PutUint16(dst[10:12], kind)
	binary.LittleEndian.PutUint32(dst[16:20], size)
	binary.LittleEndian.PutUint64(dst[20:28], requestID)
}

func parseWFPHeader(data []byte, kind uint16) (wfpDeviceHeader, error) {
	if len(data) < wfpDeviceHeaderSize || len(data) > int(WFPMaxMessageSize) {
		return wfpDeviceHeader{}, fmt.Errorf("%w: invalid message length", ErrWFPDeviceProtocol)
	}
	header := wfpDeviceHeader{
		Kind: binary.LittleEndian.Uint16(data[10:12]), Flags: binary.LittleEndian.Uint32(data[12:16]),
		TotalSize: binary.LittleEndian.Uint32(data[16:20]), RequestID: binary.LittleEndian.Uint64(data[20:28]),
	}
	if binary.LittleEndian.Uint32(data[0:4]) != wfpDeviceMagic || binary.LittleEndian.Uint16(data[4:6]) != wfpDeviceHeaderSize ||
		binary.LittleEndian.Uint16(data[6:8]) != wfpDeviceABIMajor || binary.LittleEndian.Uint16(data[8:10]) > wfpDeviceABIMinor ||
		header.Kind != kind || header.Flags != 0 || header.TotalSize != uint32(len(data)) || header.RequestID == 0 ||
		binary.LittleEndian.Uint32(data[28:32]) != 0 {
		return wfpDeviceHeader{}, fmt.Errorf("%w: invalid header", ErrWFPDeviceProtocol)
	}
	return header, nil
}

func marshalWFPNegotiate(requestID uint64, buildID [16]byte) []byte {
	data := make([]byte, wfpNegotiateRequestSize)
	putWFPHeader(data, wfpMessageNegotiateRequest, uint32(len(data)), requestID)
	copy(data[32:48], buildID[:])
	binary.LittleEndian.PutUint64(data[48:56], wfpRequiredCapabilities)
	binary.LittleEndian.PutUint32(data[56:60], wfpDefaultQueueCapacity)
	binary.LittleEndian.PutUint32(data[60:64], wfpDefaultVerdictMS)
	return data
}

func parseWFPNegotiate(data []byte, requestID uint64) (wfpNegotiateResponse, error) {
	header, err := parseWFPHeader(data, wfpMessageNegotiateResponse)
	if err != nil || len(data) != wfpNegotiateResponseSize || header.RequestID != requestID {
		return wfpNegotiateResponse{}, fmt.Errorf("%w: invalid negotiate response", ErrWFPDeviceProtocol)
	}
	var response wfpNegotiateResponse
	copy(response.BuildID[:], data[32:48])
	response.Capabilities = binary.LittleEndian.Uint64(data[48:56])
	response.MaxMessageSize = binary.LittleEndian.Uint32(data[56:60])
	response.QueueCapacity = binary.LittleEndian.Uint32(data[60:64])
	response.VerdictMS = binary.LittleEndian.Uint32(data[64:68])
	response.FailPolicy = binary.LittleEndian.Uint32(data[68:72])
	copy(response.ServiceSIDHash[:], data[72:104])
	if response.Capabilities != wfpRequiredCapabilities || response.MaxMessageSize != WFPMaxMessageSize ||
		response.QueueCapacity == 0 || response.QueueCapacity > wfpDefaultQueueCapacity || response.VerdictMS < 25 || response.VerdictMS > 1000 ||
		response.FailPolicy != 1 || response.BuildID != wfpDriverBuildID || response.ServiceSIDHash != wfpHelperServiceSIDHash {
		return wfpNegotiateResponse{}, fmt.Errorf("%w: incompatible capabilities", ErrWFPDeviceProtocol)
	}
	return response, nil
}

func marshalWFPDisablePolicy(requestID uint64, policy WFPPolicy) ([]byte, error) {
	if requestID == 0 || policy.Generation == 0 || policy.LeaseNonce == ([16]byte{}) {
		return nil, fmt.Errorf("%w: invalid disable policy identity", ErrWFPDeviceProtocol)
	}
	data := make([]byte, wfpDisablePolicySize)
	putWFPHeader(data, wfpMessageDisablePolicy, uint32(len(data)), requestID)
	binary.LittleEndian.PutUint64(data[32:40], policy.Generation)
	copy(data[40:56], policy.LeaseNonce[:])
	return data, nil
}

func marshalWFPPolicy(requestID, generation uint64, nonce [16]byte, entries []wfpPolicyEntry) ([]byte, error) {
	if generation == 0 || nonce == ([16]byte{}) || len(entries) == 0 || len(entries) > 1024 {
		return nil, fmt.Errorf("%w: invalid policy identity", ErrWFPDeviceProtocol)
	}
	data := make([]byte, wfpPolicyHeaderSize+len(entries)*wfpPolicyEntrySize)
	putWFPHeader(data, wfpMessagePolicy, uint32(len(data)), requestID)
	binary.LittleEndian.PutUint64(data[32:40], generation)
	copy(data[40:56], nonce[:])
	binary.LittleEndian.PutUint32(data[56:60], uint32(len(entries)))
	for index, entry := range entries {
		offset := wfpPolicyHeaderSize + index*wfpPolicyEntrySize
		binary.LittleEndian.PutUint64(data[offset:offset+8], entry.ProcessID)
		binary.LittleEndian.PutUint64(data[offset+8:offset+16], entry.ProcessStart)
		copy(data[offset+16:offset+48], entry.AppIDHash[:])
		copy(data[offset+48:offset+80], entry.UserSecurityDescriptorHash[:])
		binary.LittleEndian.PutUint32(data[offset+80:offset+84], entry.MatchFlags)
	}
	return data, nil
}

func parseWFPCapture(data []byte) (wfpCaptureFrame, error) {
	header, err := parseWFPHeader(data, wfpMessageCapture)
	if err != nil || len(data) < wfpCaptureHeaderSize {
		return wfpCaptureFrame{}, fmt.Errorf("%w: invalid capture frame", ErrWFPDeviceProtocol)
	}
	if payloadSize := binary.LittleEndian.Uint32(data[216:220]); payloadSize != uint32(len(data)-wfpCaptureHeaderSize) || binary.LittleEndian.Uint32(data[220:224]) != 0 {
		return wfpCaptureFrame{}, fmt.Errorf("%w: capture payload length mismatch", ErrWFPDeviceProtocol)
	}
	var frame wfpCaptureFrame
	frame.RequestID = header.RequestID
	copy(frame.FlowID[:], data[32:48])
	frame.Generation = binary.LittleEndian.Uint64(data[48:56])
	copy(frame.LeaseNonce[:], data[56:72])
	frame.Sequence = binary.LittleEndian.Uint64(data[72:80])
	frame.ProcessID = binary.LittleEndian.Uint64(data[80:88])
	frame.ProcessStart = binary.LittleEndian.Uint64(data[88:96])
	copy(frame.AppIDHash[:], data[96:128])
	copy(frame.UserSecurityDescriptorHash[:], data[128:160])
	frame.AddressFamily = binary.LittleEndian.Uint16(data[160:162])
	frame.Direction, frame.Protocol = data[162], data[163]
	frame.InjectionState = binary.LittleEndian.Uint32(data[164:168])
	frame.CompartmentID = binary.LittleEndian.Uint32(data[168:172])
	frame.InterfaceIndex = binary.LittleEndian.Uint32(data[172:176])
	frame.SubInterface = binary.LittleEndian.Uint32(data[176:180])
	copy(frame.LocalAddress[:], data[180:196])
	copy(frame.RemoteAddress[:], data[196:212])
	frame.LocalPort = binary.LittleEndian.Uint16(data[212:214])
	frame.RemotePort = binary.LittleEndian.Uint16(data[214:216])
	frame.Payload = append([]byte(nil), data[wfpCaptureHeaderSize:]...)
	if frame.Generation == 0 || frame.LeaseNonce == ([16]byte{}) || frame.FlowID == ([16]byte{}) || frame.Sequence == 0 ||
		frame.ProcessID == 0 || frame.Protocol != 17 || frame.Direction != 1 || (frame.AddressFamily != 2 && frame.AddressFamily != 23) || frame.InjectionState != 0 {
		clear(frame.Payload)
		return wfpCaptureFrame{}, fmt.Errorf("%w: invalid capture identity", ErrWFPDeviceProtocol)
	}
	return frame, nil
}

func marshalWFPVerdict(frame wfpCaptureFrame, action uint32, payload []byte) ([]byte, error) {
	if action < wfpVerdictTunnel || action > wfpVerdictDrop || len(payload) != 0 {
		return nil, fmt.Errorf("%w: invalid verdict", ErrWFPDeviceProtocol)
	}
	data := make([]byte, wfpVerdictHeaderSize+len(payload))
	putWFPHeader(data, wfpMessageVerdict, uint32(len(data)), frame.RequestID)
	copy(data[32:48], frame.FlowID[:])
	binary.LittleEndian.PutUint64(data[48:56], frame.Generation)
	copy(data[56:72], frame.LeaseNonce[:])
	binary.LittleEndian.PutUint64(data[72:80], frame.Sequence)
	binary.LittleEndian.PutUint32(data[80:84], action)
	binary.LittleEndian.PutUint32(data[88:92], uint32(len(payload)))
	copy(data[wfpVerdictHeaderSize:], payload)
	return data, nil
}

func wfpFrameEndpoints(frame wfpCaptureFrame) (netip.AddrPort, netip.AddrPort, error) {
	var local, remote netip.Addr
	if frame.AddressFamily == 2 {
		local, remote = netip.AddrFrom4([4]byte(frame.LocalAddress[:4])), netip.AddrFrom4([4]byte(frame.RemoteAddress[:4]))
	} else {
		local, remote = netip.AddrFrom16(frame.LocalAddress), netip.AddrFrom16(frame.RemoteAddress)
	}
	if !local.IsValid() || !remote.IsValid() || frame.LocalPort == 0 || frame.RemotePort == 0 {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: invalid endpoints", ErrWFPDeviceProtocol)
	}
	return netip.AddrPortFrom(local, frame.LocalPort), netip.AddrPortFrom(remote, frame.RemotePort), nil
}

func hashWFPIdentity(value []byte) [32]byte { return sha256.Sum256(value) }
