package pipeline

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
)

var (
	ErrPacketTooShort      = errors.New("packet too short")
	ErrUnsupportedIP       = errors.New("unsupported ip version")
	ErrUnsupportedProtocol = errors.New("unsupported transport protocol")
)

func ParseFlow(packet []byte) (pidtrack.FlowKey, error) {
	if len(packet) < 1 {
		return pidtrack.FlowKey{}, ErrPacketTooShort
	}

	switch packet[0] >> 4 {
	case 4:
		return parseIPv4Flow(packet)
	case 6:
		return parseIPv6Flow(packet)
	default:
		return pidtrack.FlowKey{}, ErrUnsupportedIP
	}
}

func ExtractUDPPayload(packet []byte) (pidtrack.FlowKey, []byte, error) {
	if len(packet) < 1 {
		return pidtrack.FlowKey{}, nil, ErrPacketTooShort
	}

	switch packet[0] >> 4 {
	case 4:
		return extractIPv4UDPPayload(packet)
	case 6:
		return extractIPv6UDPPayload(packet)
	default:
		return pidtrack.FlowKey{}, nil, ErrUnsupportedIP
	}
}

func parseIPv4Flow(packet []byte) (pidtrack.FlowKey, error) {
	if len(packet) < 20 {
		return pidtrack.FlowKey{}, ErrPacketTooShort
	}

	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return pidtrack.FlowKey{}, ErrPacketTooShort
	}

	transport, err := transportFromIPProtocol(packet[9])
	if err != nil {
		return pidtrack.FlowKey{}, err
	}

	src := netip.AddrFrom4([4]byte(packet[12:16]))
	dst := netip.AddrFrom4([4]byte(packet[16:20]))
	return pidtrack.FlowKey{
		Transport:  transport,
		LocalIP:    src.String(),
		LocalPort:  binary.BigEndian.Uint16(packet[ihl : ihl+2]),
		RemoteIP:   dst.String(),
		RemotePort: binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]),
	}, nil
}

func extractIPv4UDPPayload(packet []byte) (pidtrack.FlowKey, []byte, error) {
	flow, err := parseIPv4Flow(packet)
	if err != nil {
		return pidtrack.FlowKey{}, nil, err
	}
	if flow.Transport != pidtrack.TransportUDP {
		return pidtrack.FlowKey{}, nil, ErrUnsupportedProtocol
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+8 {
		return pidtrack.FlowKey{}, nil, ErrPacketTooShort
	}
	udpLen := int(binary.BigEndian.Uint16(packet[ihl+4 : ihl+6]))
	if udpLen < 8 || len(packet) < ihl+udpLen {
		return pidtrack.FlowKey{}, nil, ErrPacketTooShort
	}
	return flow, append([]byte(nil), packet[ihl+8:ihl+udpLen]...), nil
}

func parseIPv6Flow(packet []byte) (pidtrack.FlowKey, error) {
	if len(packet) < 44 {
		return pidtrack.FlowKey{}, ErrPacketTooShort
	}

	transport, err := transportFromIPProtocol(packet[6])
	if err != nil {
		return pidtrack.FlowKey{}, fmt.Errorf("%w: ipv6 next header %d", err, packet[6])
	}

	var srcBytes [16]byte
	var dstBytes [16]byte
	copy(srcBytes[:], packet[8:24])
	copy(dstBytes[:], packet[24:40])
	src := netip.AddrFrom16(srcBytes)
	dst := netip.AddrFrom16(dstBytes)

	return pidtrack.FlowKey{
		Transport:  transport,
		LocalIP:    src.String(),
		LocalPort:  binary.BigEndian.Uint16(packet[40:42]),
		RemoteIP:   dst.String(),
		RemotePort: binary.BigEndian.Uint16(packet[42:44]),
	}, nil
}

func extractIPv6UDPPayload(packet []byte) (pidtrack.FlowKey, []byte, error) {
	flow, err := parseIPv6Flow(packet)
	if err != nil {
		return pidtrack.FlowKey{}, nil, err
	}
	if flow.Transport != pidtrack.TransportUDP {
		return pidtrack.FlowKey{}, nil, ErrUnsupportedProtocol
	}
	if len(packet) < 48 {
		return pidtrack.FlowKey{}, nil, ErrPacketTooShort
	}
	udpLen := int(binary.BigEndian.Uint16(packet[44:46]))
	if udpLen < 8 || len(packet) < 40+udpLen {
		return pidtrack.FlowKey{}, nil, ErrPacketTooShort
	}
	return flow, append([]byte(nil), packet[48:40+udpLen]...), nil
}

func transportFromIPProtocol(proto byte) (pidtrack.Transport, error) {
	switch proto {
	case 6:
		return pidtrack.TransportTCP, nil
	case 17:
		return pidtrack.TransportUDP, nil
	default:
		return "", ErrUnsupportedProtocol
	}
}
