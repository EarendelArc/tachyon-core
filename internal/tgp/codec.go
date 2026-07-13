package tgp

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	outerHeaderSize       = 13
	innerHeaderSize       = 43
	MaxTGPDatagramSize    = 1452
	maxTGPDataPayloadSize = MaxTGPDatagramSize - outerHeaderSize - innerHeaderSize - chacha20poly1305.Overhead
	maxDTLSSequence       = 1<<48 - 1
)

var (
	ErrPacketTooShort   = errors.New("tgp packet too short")
	ErrInvalidMagic     = errors.New("invalid tgp magic")
	ErrInvalidLength    = errors.New("invalid tgp length")
	ErrSequenceOverflow = errors.New("dtls sequence number exceeds 48 bits")
	ErrDatagramTooLarge = errors.New("tgp datagram exceeds protocol limit")
)

type Codec struct {
	aead cipher.AEAD
}

func NewCodec(key [trafficKeySize]byte) (*Codec, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("create chacha20-poly1305 aead: %w", err)
	}
	return &Codec{aead: aead}, nil
}

func NewOuterHeader(sequence uint64, encryptedLength int) (OuterHeader, error) {
	if sequence > maxDTLSSequence {
		return OuterHeader{}, ErrSequenceOverflow
	}
	if encryptedLength < 0 || encryptedLength > 0xffff {
		return OuterHeader{}, ErrInvalidLength
	}
	var seq [6]byte
	seq[0] = byte(sequence >> 40)
	seq[1] = byte(sequence >> 32)
	seq[2] = byte(sequence >> 24)
	seq[3] = byte(sequence >> 16)
	seq[4] = byte(sequence >> 8)
	seq[5] = byte(sequence)
	return OuterHeader{
		ContentType:  0x17,
		VersionMajor: 0xfe,
		VersionMinor: 0xff,
		Epoch:        0,
		SequenceNum:  seq,
		Length:       uint16(encryptedLength),
	}, nil
}

func NewDataHeader(sessionID SessionID, streamID StreamID, packetNumber uint64, payloadLength int) (InnerHeader, error) {
	if payloadLength < 0 || payloadLength > 0xffff {
		return InnerHeader{}, ErrInvalidLength
	}
	return InnerHeader{
		Magic:         Magic,
		Flags:         FlagEncrypted,
		SessionID:     sessionID,
		StreamID:      streamID,
		PacketNumber:  packetNumber,
		PayloadLength: uint16(payloadLength),
	}, nil
}

func (c *Codec) Seal(sequence uint64, inner InnerHeader, payload []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("nil tgp codec")
	}
	if len(payload) > 0xffff {
		return nil, ErrInvalidLength
	}
	wireSize := outerHeaderSize + innerHeaderSize + len(payload) + c.aead.Overhead()
	if wireSize > MaxTGPDatagramSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrDatagramTooLarge, wireSize, MaxTGPDatagramSize)
	}
	inner.PayloadLength = uint16(len(payload))
	inner.Flags |= FlagEncrypted

	plaintext := make([]byte, innerHeaderSize+len(payload))
	marshalInnerHeader(plaintext[:innerHeaderSize], inner)
	copy(plaintext[innerHeaderSize:], payload)

	encryptedLength := len(plaintext) + c.aead.Overhead()
	outer, err := NewOuterHeader(sequence, encryptedLength)
	if err != nil {
		return nil, err
	}
	outerBytes := marshalOuterHeader(outer)
	nonce := nonceFromOuter(outer)

	out := make([]byte, 0, outerHeaderSize+encryptedLength)
	out = append(out, outerBytes...)
	out = c.aead.Seal(out, nonce[:], plaintext, outerBytes)
	return out, nil
}

func (c *Codec) Open(wire []byte) (Packet, error) {
	if c == nil || c.aead == nil {
		return Packet{}, errors.New("nil tgp codec")
	}
	if len(wire) > MaxTGPDatagramSize {
		return Packet{}, fmt.Errorf("%w: %d > %d", ErrDatagramTooLarge, len(wire), MaxTGPDatagramSize)
	}
	if len(wire) < outerHeaderSize+c.aead.Overhead()+innerHeaderSize {
		return Packet{}, ErrPacketTooShort
	}

	outer, err := parseOuterHeader(wire[:outerHeaderSize])
	if err != nil {
		return Packet{}, err
	}
	if int(outer.Length) != len(wire)-outerHeaderSize {
		return Packet{}, ErrInvalidLength
	}

	outerBytes := wire[:outerHeaderSize]
	nonce := nonceFromOuter(outer)
	plaintext, err := c.aead.Open(nil, nonce[:], wire[outerHeaderSize:], outerBytes)
	if err != nil {
		return Packet{}, err
	}
	if len(plaintext) < innerHeaderSize {
		return Packet{}, ErrPacketTooShort
	}

	inner, err := parseInnerHeader(plaintext[:innerHeaderSize])
	if err != nil {
		return Packet{}, err
	}
	if int(inner.PayloadLength) != len(plaintext)-innerHeaderSize {
		return Packet{}, ErrInvalidLength
	}

	payload := append([]byte(nil), plaintext[innerHeaderSize:]...)
	return Packet{
		Outer:      outer,
		Inner:      inner,
		Payload:    payload,
		ReceivedAt: time.Now(),
	}, nil
}

func marshalOuterHeader(h OuterHeader) []byte {
	out := make([]byte, outerHeaderSize)
	out[0] = h.ContentType
	out[1] = h.VersionMajor
	out[2] = h.VersionMinor
	binary.BigEndian.PutUint16(out[3:5], h.Epoch)
	copy(out[5:11], h.SequenceNum[:])
	binary.BigEndian.PutUint16(out[11:13], h.Length)
	return out
}

func parseOuterHeader(data []byte) (OuterHeader, error) {
	if len(data) < outerHeaderSize {
		return OuterHeader{}, ErrPacketTooShort
	}
	var h OuterHeader
	h.ContentType = data[0]
	h.VersionMajor = data[1]
	h.VersionMinor = data[2]
	h.Epoch = binary.BigEndian.Uint16(data[3:5])
	copy(h.SequenceNum[:], data[5:11])
	h.Length = binary.BigEndian.Uint16(data[11:13])
	return h, nil
}

func marshalInnerHeader(out []byte, h InnerHeader) {
	copy(out[0:4], h.Magic[:])
	out[4] = h.Flags
	out[5] = 0
	out[6] = 0
	copy(out[7:23], h.SessionID[:])
	binary.BigEndian.PutUint16(out[23:25], uint16(h.StreamID))
	binary.BigEndian.PutUint64(out[25:33], h.PacketNumber)
	binary.BigEndian.PutUint32(out[33:37], h.FECGroup)
	out[37] = h.FECIndex
	out[38] = h.FECTotal
	out[39] = h.FECDataShards
	out[40] = 0
	binary.BigEndian.PutUint16(out[41:43], h.PayloadLength)
}

func parseInnerHeader(data []byte) (InnerHeader, error) {
	if len(data) < innerHeaderSize {
		return InnerHeader{}, ErrPacketTooShort
	}
	var h InnerHeader
	copy(h.Magic[:], data[0:4])
	if subtle.ConstantTimeCompare(h.Magic[:], Magic[:]) != 1 {
		return InnerHeader{}, ErrInvalidMagic
	}
	h.Flags = data[4]
	copy(h.SessionID[:], data[7:23])
	h.StreamID = StreamID(binary.BigEndian.Uint16(data[23:25]))
	h.PacketNumber = binary.BigEndian.Uint64(data[25:33])
	h.FECGroup = binary.BigEndian.Uint32(data[33:37])
	h.FECIndex = data[37]
	h.FECTotal = data[38]
	h.FECDataShards = data[39]
	h.PayloadLength = binary.BigEndian.Uint16(data[41:43])
	return h, nil
}

func nonceFromOuter(h OuterHeader) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint16(nonce[0:2], h.Epoch)
	copy(nonce[2:8], h.SequenceNum[:])
	nonce[8] = h.ContentType
	nonce[9] = h.VersionMajor
	nonce[10] = h.VersionMinor
	return nonce
}
