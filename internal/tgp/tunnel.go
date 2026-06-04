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
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
	Payload    []byte
}

func MarshalTunnelDatagram(datagram TunnelDatagram) ([]byte, error) {
	if !datagram.LocalIP.IsValid() {
		return nil, fmt.Errorf("%w: invalid local ip", ErrInvalidTunnelData)
	}
	if !datagram.RemoteIP.IsValid() {
		return nil, fmt.Errorf("%w: invalid remote ip", ErrInvalidTunnelData)
	}

	localAddr := datagram.LocalIP.AsSlice()
	remoteAddr := datagram.RemoteIP.AsSlice()
	if len(localAddr) != 4 && len(localAddr) != 16 {
		return nil, fmt.Errorf("%w: unsupported local address length %d", ErrInvalidTunnelData, len(localAddr))
	}
	if len(remoteAddr) != 4 && len(remoteAddr) != 16 {
		return nil, fmt.Errorf("%w: unsupported remote address length %d", ErrInvalidTunnelData, len(remoteAddr))
	}
	out := make([]byte, 0, 4+1+len(localAddr)+2+1+len(remoteAddr)+2+len(datagram.Payload))
	out = append(out, tunnelMagic[:]...)
	out = append(out, byte(len(localAddr)))
	out = append(out, localAddr...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], datagram.LocalPort)
	out = append(out, port[:]...)
	out = append(out, byte(len(remoteAddr)))
	out = append(out, remoteAddr...)
	binary.BigEndian.PutUint16(port[:], datagram.RemotePort)
	out = append(out, port[:]...)
	out = append(out, datagram.Payload...)
	return out, nil
}

func ParseTunnelDatagram(data []byte) (TunnelDatagram, error) {
	if len(data) < 4+1+2+1+2 {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	if string(data[:4]) != string(tunnelMagic[:]) {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	localLen := int(data[4])
	if localLen != 4 && localLen != 16 {
		return TunnelDatagram{}, fmt.Errorf("%w: unsupported local address length %d", ErrInvalidTunnelData, localLen)
	}
	if len(data) < 4+1+localLen+2+1+2 {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	var localIP netip.Addr
	if localLen == 4 {
		var raw [4]byte
		copy(raw[:], data[5:9])
		localIP = netip.AddrFrom4(raw)
	} else {
		var raw [16]byte
		copy(raw[:], data[5:21])
		localIP = netip.AddrFrom16(raw)
	}
	localPortOffset := 5 + localLen
	localPort := binary.BigEndian.Uint16(data[localPortOffset : localPortOffset+2])

	remoteLenOffset := localPortOffset + 2
	remoteLen := int(data[remoteLenOffset])
	if remoteLen != 4 && remoteLen != 16 {
		return TunnelDatagram{}, fmt.Errorf("%w: unsupported remote address length %d", ErrInvalidTunnelData, remoteLen)
	}
	remoteOffset := remoteLenOffset + 1
	remotePortOffset := remoteOffset + remoteLen
	if len(data) < remotePortOffset+2 {
		return TunnelDatagram{}, ErrInvalidTunnelData
	}
	var remoteIP netip.Addr
	if remoteLen == 4 {
		var raw [4]byte
		copy(raw[:], data[remoteOffset:remotePortOffset])
		remoteIP = netip.AddrFrom4(raw)
	} else {
		var raw [16]byte
		copy(raw[:], data[remoteOffset:remotePortOffset])
		remoteIP = netip.AddrFrom16(raw)
	}
	return TunnelDatagram{
		LocalIP:    localIP,
		LocalPort:  localPort,
		RemoteIP:   remoteIP,
		RemotePort: binary.BigEndian.Uint16(data[remotePortOffset : remotePortOffset+2]),
		Payload:    append([]byte(nil), data[remotePortOffset+2:]...),
	}, nil
}

func (d TunnelDatagram) LocalAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(d.LocalIP, d.LocalPort)
}

func (d TunnelDatagram) RemoteAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(d.RemoteIP, d.RemotePort)
}
