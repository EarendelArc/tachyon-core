package capturedudp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

const (
	NamedPipeProtocolVersion uint16 = 1
	NamedPipeMaxFramePayload        = 64 << 10
	namedPipeFrameHeaderSize        = 12
	namedPipeDefaultTimeout         = 10 * time.Second
	namedPipeMaxTimeout             = 30 * time.Second
	namedPipeMaxIdleTimeout         = 24 * time.Hour
)

var (
	ErrNamedPipeUnsupported = errors.New("captured UDP named pipe transport is unsupported on this platform")
	ErrNamedPipeProtocol    = errors.New("captured UDP named pipe protocol violation")
	ErrNamedPipeIdentity    = errors.New("captured UDP named pipe peer identity rejected")
	ErrNamedPipeTimeout     = errors.New("captured UDP named pipe operation timed out")
	ErrNamedPipeCanceled    = errors.New("captured UDP named pipe operation canceled")
)

type NamedPipeConfig struct {
	Name                 string
	AllowedSIDs          []string
	MinimumIntegrityRID  uint32
	OperationTimeout     time.Duration
	IdleTimeout          time.Duration
	AllowInsecureUserSID bool
}

type NamedPipeServer interface {
	Run(context.Context) error
	Close() error
}

func (config NamedPipeConfig) normalized() (NamedPipeConfig, error) {
	if !validNamedPipeName(config.Name) {
		return NamedPipeConfig{}, fmt.Errorf("%w: invalid pipe name", ErrNamedPipeProtocol)
	}
	if len(config.AllowedSIDs) == 0 || len(config.AllowedSIDs) > 16 {
		return NamedPipeConfig{}, fmt.Errorf("%w: allowed SID count must be between 1 and 16", ErrNamedPipeIdentity)
	}
	config.AllowedSIDs = append([]string(nil), config.AllowedSIDs...)
	seen := make(map[string]struct{}, len(config.AllowedSIDs))
	for index, sid := range config.AllowedSIDs {
		sid = strings.TrimSpace(sid)
		if sid == "" || len(sid) > 184 {
			return NamedPipeConfig{}, fmt.Errorf("%w: invalid allowed SID", ErrNamedPipeIdentity)
		}
		if _, exists := seen[sid]; exists {
			return NamedPipeConfig{}, fmt.Errorf("%w: duplicate allowed SID", ErrNamedPipeIdentity)
		}
		seen[sid] = struct{}{}
		config.AllowedSIDs[index] = sid
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = namedPipeDefaultTimeout
	}
	if config.OperationTimeout > namedPipeMaxTimeout {
		return NamedPipeConfig{}, fmt.Errorf("%w: operation timeout exceeds %s", ErrNamedPipeProtocol, namedPipeMaxTimeout)
	}
	if config.IdleTimeout < 0 || config.IdleTimeout > namedPipeMaxIdleTimeout {
		return NamedPipeConfig{}, fmt.Errorf("%w: idle timeout must be between 0 and %s", ErrNamedPipeProtocol, namedPipeMaxIdleTimeout)
	}
	return config, nil
}

func validNamedPipeName(name string) bool {
	const prefix = `\\.\pipe\Tachyon\`
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == "" || len(suffix) > 96 {
		return false
	}
	for _, character := range suffix {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

type namedPipeMessageType uint16

const (
	pipeMessageHello namedPipeMessageType = iota + 1
	pipeMessageAuthenticate
	pipeMessagePrepareGeneration
	pipeMessageCommitGeneration
	pipeMessageAbortGeneration
	pipeMessageDisableGeneration
	pipeMessageOpenFlow
	pipeMessageDatagram
	pipeMessageReply
	pipeMessageCloseFlow
	pipeMessageCloseConnection
	pipeMessagePing
	pipeMessagePong
	pipeMessageResponse namedPipeMessageType = 0x8000
)

func (messageType namedPipeMessageType) valid() bool {
	switch messageType {
	case pipeMessageHello, pipeMessageAuthenticate, pipeMessagePrepareGeneration,
		pipeMessageCommitGeneration, pipeMessageAbortGeneration, pipeMessageDisableGeneration, pipeMessageOpenFlow,
		pipeMessageDatagram, pipeMessageReply, pipeMessageCloseFlow,
		pipeMessageCloseConnection, pipeMessagePing, pipeMessagePong, pipeMessageResponse:
		return true
	default:
		return false
	}
}

type namedPipeStatus uint16

const (
	pipeStatusOK namedPipeStatus = iota
	pipeStatusProtocol
	pipeStatusAuthentication
	pipeStatusUnauthorized
	pipeStatusInvalid
	pipeStatusConflict
	pipeStatusStale
	pipeStatusLimit
	pipeStatusTimeout
	pipeStatusCanceled
	pipeStatusInternal
)

type namedPipeFrame struct {
	Type    namedPipeMessageType
	Payload []byte
}

type namedPipeFrameIO interface {
	ReadFull(context.Context, []byte) error
	WriteFull(context.Context, []byte) error
}

func readNamedPipeFrame(ctx context.Context, transport namedPipeFrameIO) (namedPipeFrame, error) {
	header := make([]byte, namedPipeFrameHeaderSize)
	if err := transport.ReadFull(ctx, header); err != nil {
		return namedPipeFrame{}, err
	}
	messageType, payloadLength, err := decodeNamedPipeHeader(header)
	if err != nil {
		return namedPipeFrame{}, err
	}
	payload := make([]byte, payloadLength)
	if payloadLength != 0 {
		if err := transport.ReadFull(ctx, payload); err != nil {
			return namedPipeFrame{}, err
		}
	}
	return namedPipeFrame{Type: messageType, Payload: payload}, nil
}

func writeNamedPipeFrame(ctx context.Context, transport namedPipeFrameIO, frame namedPipeFrame) error {
	encoded, err := marshalNamedPipeFrame(frame)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return transport.WriteFull(ctx, encoded)
}

func marshalNamedPipeFrame(frame namedPipeFrame) ([]byte, error) {
	if !frame.Type.valid() {
		return nil, fmt.Errorf("%w: unknown message type %d", ErrNamedPipeProtocol, frame.Type)
	}
	if len(frame.Payload) > NamedPipeMaxFramePayload {
		return nil, fmt.Errorf("%w: frame payload %d exceeds %d", ErrNamedPipeProtocol, len(frame.Payload), NamedPipeMaxFramePayload)
	}
	encoded := make([]byte, namedPipeFrameHeaderSize+len(frame.Payload))
	copy(encoded[:4], "TCU1")
	binary.BigEndian.PutUint16(encoded[4:6], NamedPipeProtocolVersion)
	binary.BigEndian.PutUint16(encoded[6:8], uint16(frame.Type))
	binary.BigEndian.PutUint32(encoded[8:12], uint32(len(frame.Payload)))
	copy(encoded[namedPipeFrameHeaderSize:], frame.Payload)
	return encoded, nil
}

func decodeNamedPipeFrame(encoded []byte) (namedPipeFrame, error) {
	if len(encoded) < namedPipeFrameHeaderSize {
		return namedPipeFrame{}, fmt.Errorf("%w: truncated frame header", ErrNamedPipeProtocol)
	}
	messageType, payloadLength, err := decodeNamedPipeHeader(encoded[:namedPipeFrameHeaderSize])
	if err != nil {
		return namedPipeFrame{}, err
	}
	if len(encoded) != namedPipeFrameHeaderSize+payloadLength {
		return namedPipeFrame{}, fmt.Errorf("%w: frame length mismatch", ErrNamedPipeProtocol)
	}
	payload := append([]byte(nil), encoded[namedPipeFrameHeaderSize:]...)
	return namedPipeFrame{Type: messageType, Payload: payload}, nil
}

func decodeNamedPipeHeader(header []byte) (namedPipeMessageType, int, error) {
	if len(header) != namedPipeFrameHeaderSize || string(header[:4]) != "TCU1" {
		return 0, 0, fmt.Errorf("%w: invalid frame magic", ErrNamedPipeProtocol)
	}
	if version := binary.BigEndian.Uint16(header[4:6]); version != NamedPipeProtocolVersion {
		return 0, 0, fmt.Errorf("%w: unsupported frame version %d", ErrNamedPipeProtocol, version)
	}
	messageType := namedPipeMessageType(binary.BigEndian.Uint16(header[6:8]))
	if !messageType.valid() {
		return 0, 0, fmt.Errorf("%w: unknown message type %d", ErrNamedPipeProtocol, messageType)
	}
	payloadLength := binary.BigEndian.Uint32(header[8:12])
	if payloadLength > NamedPipeMaxFramePayload {
		return 0, 0, fmt.Errorf("%w: frame payload %d exceeds %d", ErrNamedPipeProtocol, payloadLength, NamedPipeMaxFramePayload)
	}
	return messageType, int(payloadLength), nil
}

type pipeDecoder struct {
	payload []byte
	offset  int
}

func (decoder *pipeDecoder) take(size int) ([]byte, error) {
	if size < 0 || decoder.offset > len(decoder.payload)-size {
		return nil, fmt.Errorf("%w: truncated message", ErrNamedPipeProtocol)
	}
	value := decoder.payload[decoder.offset : decoder.offset+size]
	decoder.offset += size
	return value, nil
}

func (decoder *pipeDecoder) uint8() (uint8, error) {
	value, err := decoder.take(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (decoder *pipeDecoder) uint64() (uint64, error) {
	value, err := decoder.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}

func (decoder *pipeDecoder) done() error {
	if decoder.offset != len(decoder.payload) {
		return fmt.Errorf("%w: trailing message bytes", ErrNamedPipeProtocol)
	}
	return nil
}

func appendUint16(destination []byte, value uint16) []byte {
	return binary.BigEndian.AppendUint16(destination, value)
}

func appendUint64(destination []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(destination, value)
}

func appendRequestID(destination []byte, requestID uint64) []byte {
	return appendUint64(destination, requestID)
}

func decodeRequest(frame namedPipeFrame) (uint64, *pipeDecoder, error) {
	decoder := &pipeDecoder{payload: frame.Payload}
	requestID, err := decoder.uint64()
	if err != nil || requestID == 0 {
		return 0, nil, fmt.Errorf("%w: invalid request ID", ErrNamedPipeProtocol)
	}
	return requestID, decoder, nil
}

func appendAddrPort(destination []byte, address netip.AddrPort, family AddressFamily) ([]byte, error) {
	if !address.IsValid() || address.Port() == 0 {
		return nil, ErrInvalidFlow
	}
	switch family {
	case AddressFamilyIPv4:
		if !address.Addr().Is4() {
			return nil, ErrInvalidFlow
		}
		value := address.Addr().As4()
		destination = append(destination, value[:]...)
	case AddressFamilyIPv6:
		if !address.Addr().Is6() || address.Addr().Is4In6() {
			return nil, ErrInvalidFlow
		}
		value := address.Addr().As16()
		destination = append(destination, value[:]...)
	default:
		return nil, ErrInvalidFlow
	}
	return appendUint16(destination, address.Port()), nil
}

func decodeAddrPort(decoder *pipeDecoder, family AddressFamily) (netip.AddrPort, error) {
	addressSize := 0
	switch family {
	case AddressFamilyIPv4:
		addressSize = 4
	case AddressFamilyIPv6:
		addressSize = 16
	default:
		return netip.AddrPort{}, ErrInvalidFlow
	}
	addressBytes, err := decoder.take(addressSize)
	if err != nil {
		return netip.AddrPort{}, err
	}
	portBytes, err := decoder.take(2)
	if err != nil {
		return netip.AddrPort{}, err
	}
	address, ok := netip.AddrFromSlice(addressBytes)
	port := binary.BigEndian.Uint16(portBytes)
	if !ok || port == 0 {
		return netip.AddrPort{}, ErrInvalidFlow
	}
	return netip.AddrPortFrom(address.Unmap(), port), nil
}

func statusForError(err error) namedPipeStatus {
	switch {
	case err == nil:
		return pipeStatusOK
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrNamedPipeTimeout):
		return pipeStatusTimeout
	case errors.Is(err, context.Canceled), errors.Is(err, ErrNamedPipeCanceled):
		return pipeStatusCanceled
	case errors.Is(err, ErrAuthentication), errors.Is(err, ErrTransportNotVerified), errors.Is(err, ErrNamedPipeIdentity):
		return pipeStatusAuthentication
	case errors.Is(err, ErrControllerRevoked), errors.Is(err, ErrTransportMismatch):
		return pipeStatusUnauthorized
	case errors.Is(err, ErrInvalidFlow), errors.Is(err, ErrInvalidGeneration), errors.Is(err, ErrMissingLeaseIdentity), errors.Is(err, ErrNamedPipeProtocol):
		return pipeStatusInvalid
	case errors.Is(err, ErrDuplicateFlow), errors.Is(err, ErrTransactionActive), errors.Is(err, ErrControllerActive), errors.Is(err, ErrTransportActive):
		return pipeStatusConflict
	case errors.Is(err, ErrUnknownFlow), errors.Is(err, ErrStaleGeneration), errors.Is(err, ErrUnknownTransaction), errors.Is(err, ErrAttachmentStale):
		return pipeStatusStale
	case errors.Is(err, ErrDatagramTooLarge), errors.Is(err, ErrFlowLimit), errors.Is(err, ErrBufferBudget), errors.Is(err, ErrOutstandingBudget), errors.Is(err, ErrRateLimit):
		return pipeStatusLimit
	default:
		return pipeStatusInternal
	}
}

func namedPipeResponse(requestID uint64, operation namedPipeMessageType, status namedPipeStatus, data []byte) namedPipeFrame {
	payload := make([]byte, 0, 12+len(data))
	payload = appendUint64(payload, requestID)
	payload = appendUint16(payload, uint16(operation))
	payload = appendUint16(payload, uint16(status))
	payload = append(payload, data...)
	return namedPipeFrame{Type: pipeMessageResponse, Payload: payload}
}

func isNamedPipeEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func marshalTunnelForPipe(datagram tgp.TunnelDatagram) ([]byte, error) {
	encoded, err := tgp.MarshalTunnelDatagram(datagram)
	if err != nil {
		return nil, err
	}
	if len(encoded) > NamedPipeMaxFramePayload-12 {
		return nil, ErrDatagramTooLarge
	}
	return encoded, nil
}
