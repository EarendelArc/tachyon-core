package tgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

var (
	tunnelMagic          = [4]byte{0x54, 0x47, 0x44, 0x01} // "TGD\x01"
	ErrInvalidTunnelData = errors.New("invalid tgp tunnel datagram")
)

type TunnelDatagram struct {
	RemoteIP   netip.Addr
	RemotePort uint16
	Payload    []byte
}

func MarshalTunnelDatagram(datagram TunnelDatagram) ([]byte, error) {
	if !datagram.RemoteIP.IsValid() {
		return nil, fmt.Errorf("%w: invalid remote ip", ErrInvalidTunnelData)
	}

	addr := datagram.RemoteIP.AsSlice()
	if len(addr) != 4 && len(addr) != 16 {
		return nil, fmt.Errorf("%w: unsupported address length %d", ErrInvalidTunnelData, len(addr))
	}
	out := make([]byte, 0, 4+1+len(addr)+2+len(datagram.Payload))
	out = append(out, tunnelMagic[:]...)
	out = append(out, byte(len(addr)))
	out = append(out, addr...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], datagram.RemotePort)
	out = append(out, port[:]...)
	out = append(out, datagram.Payload...)
	return out, nil
}

func ParseTunnelDatagram(data []byte) (TunnelDatagram, error) {
	if len(data) < 4+1+2 {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	if string(data[:4]) != string(tunnelMagic[:]) {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	addrLen := int(data[4])
	if addrLen != 4 && addrLen != 16 {
		return TunnelDatagram{}, fmt.Errorf("%w: unsupported address length %d", ErrInvalidTunnelData, addrLen)
	}
	if len(data) < 4+1+addrLen+2 {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	var addr netip.Addr
	var ok bool
	if addrLen == 4 {
		var raw [4]byte
		copy(raw[:], data[5:9])
		addr = netip.AddrFrom4(raw)
		ok = true
	} else {
		var raw [16]byte
		copy(raw[:], data[5:21])
		addr = netip.AddrFrom16(raw)
		ok = true
	}
	if !ok {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	portOffset := 5 + addrLen
	return TunnelDatagram{
		RemoteIP:   addr,
		RemotePort: binary.BigEndian.Uint16(data[portOffset : portOffset+2]),
		Payload:    append([]byte(nil), data[portOffset+2:]...),
	}, nil
}

func (d TunnelDatagram) RemoteAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(d.RemoteIP, d.RemotePort)
}
