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
