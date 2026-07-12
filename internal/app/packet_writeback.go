package app

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const udpProtocol = 17

func buildUDPPacket(src netip.AddrPort, dst netip.AddrPort, payload []byte) ([]byte, error) {
	switch {
	case src.Addr().Is4() && dst.Addr().Is4():
		return buildIPv4UDPPacket(src, dst, payload)
	case src.Addr().Is6() && dst.Addr().Is6():
		return buildIPv6UDPPacket(src, dst, payload)
	default:
		return nil, fmt.Errorf("udp writeback address families differ: %s -> %s", src, dst)
	}
}

func buildIPv4UDPPacket(src netip.AddrPort, dst netip.AddrPort, payload []byte) ([]byte, error) {
	if !src.Addr().Is4() || !dst.Addr().Is4() {
		return nil, fmt.Errorf("IPv4 UDP writeback requires IPv4 source and destination")
	}
	totalLen := 20 + 8 + len(payload)
	if totalLen > 0xffff {
		return nil, fmt.Errorf("udp writeback packet too large: %d", totalLen)
	}

	packet := make([]byte, totalLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[8] = 64
	packet[9] = udpProtocol
	src4 := src.Addr().As4()
	dst4 := dst.Addr().As4()
	copy(packet[12:16], src4[:])
	copy(packet[16:20], dst4[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))

	udp := packet[20:]
	writeUDPHeader(udp, src.Port(), dst.Port(), payload)
	checksum := udpChecksumIPv4(src.Addr(), dst.Addr(), udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet, nil
}

func buildIPv6UDPPacket(src netip.AddrPort, dst netip.AddrPort, payload []byte) ([]byte, error) {
	if !src.Addr().Is6() || !dst.Addr().Is6() {
		return nil, fmt.Errorf("IPv6 UDP writeback requires IPv6 source and destination")
	}
	udpLen := 8 + len(payload)
	if udpLen > 0xffff {
		return nil, fmt.Errorf("udp writeback payload too large: %d", udpLen)
	}

	packet := make([]byte, 40+udpLen)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(udpLen))
	packet[6] = udpProtocol
	packet[7] = 64
	src6 := src.Addr().As16()
	dst6 := dst.Addr().As16()
	copy(packet[8:24], src6[:])
	copy(packet[24:40], dst6[:])

	udp := packet[40:]
	writeUDPHeader(udp, src.Port(), dst.Port(), payload)
	checksum := udpChecksumIPv6(src.Addr(), dst.Addr(), udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet, nil
}

func writeUDPHeader(udp []byte, srcPort uint16, dstPort uint16, payload []byte) {
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
}

func udpChecksumIPv4(src netip.Addr, dst netip.Addr, udp []byte) uint16 {
	src4 := src.As4()
	dst4 := dst.As4()
	sum := checksumBytes(0, src4[:])
	sum = checksumBytes(sum, dst4[:])
	sum += udpProtocol
	sum += uint32(len(udp))
	return finishChecksum(checksumBytes(sum, udp))
}

func udpChecksumIPv6(src netip.Addr, dst netip.Addr, udp []byte) uint16 {
	src6 := src.As16()
	dst6 := dst.As16()
	sum := checksumBytes(0, src6[:])
	sum = checksumBytes(sum, dst6[:])
	sum += uint32(len(udp)>>16) + uint32(len(udp)&0xffff)
	sum += udpProtocol
	return finishChecksum(checksumBytes(sum, udp))
}

func internetChecksum(data []byte) uint16 {
	return finishChecksum(checksumBytes(0, data))
}

func checksumBytes(sum uint32, data []byte) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
