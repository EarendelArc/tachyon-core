package app

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

func buildIPv4UDPPacket(src netip.AddrPort, dst netip.AddrPort, payload []byte) ([]byte, error) {
	if !src.Addr().Is4() || !dst.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 UDP writeback is implemented")
	}
	totalLen := 20 + 8 + len(payload)
	if totalLen > 0xffff {
		return nil, fmt.Errorf("udp writeback packet too large: %d", totalLen)
	}

	packet := make([]byte, totalLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[8] = 64
	packet[9] = 17
	src4 := src.Addr().As4()
	dst4 := dst.Addr().As4()
	copy(packet[12:16], src4[:])
	copy(packet[16:20], dst4[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))

	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	return packet, nil
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
