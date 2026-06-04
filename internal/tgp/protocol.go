// Package tgp defines the on-wire data structures and state-machine contracts
// for the Tachyon Game Protocol (TGP).
//
// # Design Goals
//
//   - Sub-millisecond jitter: Token-Bucket pacing keeps router queues tiny.
//   - 0-RTT loss recovery: Reed-Solomon FEC eliminates ARQ round-trips.
//   - Connection migration: UUID-based session IDs survive IP changes.
//   - Obfuscation: Outer DTLS/WebRTC-like headers defeat DPI/QoS.
//
// # Packet Layout (wire format, big-endian)
//
//	┌────────────────────────────────────────────────────────────────────┐
//	│  Outer Header (obfuscation layer – looks like DTLS Record)         │
//	│  [Content-Type:1][Version:2][Epoch:2][SequenceNum:6][Length:2]     │
//	├────────────────────────────────────────────────────────────────────┤
//	│  TGP Inner Header (after ChaCha20-Poly1305 decryption)             │
//	│  [Magic:4][Flags:1][SessionID:16][StreamID:2][PacketNum:8]         │
//	│  [FECGroup:4][FECIndex:1][FECTotal:1][FECDataShards:1][Pad:1]      │
//	│  [PayloadLen:2]                                                    │
//	├────────────────────────────────────────────────────────────────────┤
//	│  Payload (game UDP datagram)                                       │
//	└────────────────────────────────────────────────────────────────────┘
package tgp

import (
	"context"
	"net"
	"time"
)

// Magic is the 4-byte identifier embedded in every TGP inner header.
// Chosen to look like a plausible DTLS body byte sequence.
var Magic = [4]byte{0x54, 0x47, 0x50, 0x01} // "TGP\x01"

// FlagMask bit positions within the Flags byte.
const (
	FlagControl   uint8 = 1 << 0 // control/data plane: 1 = control, 0 = data
	FlagFEC       uint8 = 1 << 1 // this packet carries FEC parity data
	FlagMigrate   uint8 = 1 << 2 // client is requesting connection migration
	FlagClose     uint8 = 1 << 3 // orderly session close
	FlagMultipath uint8 = 1 << 4 // packet is a multipath duplicate; server should dedup
	FlagEncrypted uint8 = 1 << 7 // inner payload is encrypted (always set in production)
)

// SessionID is a 128-bit UUID that uniquely identifies a TGP session across
// IP address changes. This is the primary key for connection migration.
type SessionID [16]byte

// StreamID is a 16-bit identifier for multiplexed logical streams within one
// session (e.g., game data vs. voice).
type StreamID uint16

// OuterHeader mimics a DTLS Record header so that DPI inspection classifies
// TGP traffic as DTLS. All fields are big-endian on the wire.
type OuterHeader struct {
	// ContentType: 0x17 (application_data) matches DTLS obfuscation target.
	ContentType uint8
	// VersionMajor/Minor: 0xFE 0xFF = DTLS 1.0 (most common on the wire).
	VersionMajor uint8
	VersionMinor uint8
	// Epoch increments on each key change (kept at 0 for simplicity).
	Epoch uint16
	// SequenceNum is the 48-bit DTLS sequence number field.
	SequenceNum [6]byte
	// Length is the byte length of the encrypted TGP payload that follows.
	Length uint16
}

// InnerHeader is the authenticated, encrypted core of each TGP packet.
// All fields are big-endian on the wire.
type InnerHeader struct {
	Magic         [4]byte   // TGP magic bytes; validated after decryption
	Flags         uint8     // bit-field of Flag* constants above
	_             [2]byte   // reserved / explicit padding
	SessionID     SessionID // 16-byte UUID for session identification
	StreamID      StreamID  // logical stream multiplexing
	PacketNumber  uint64    // monotonically increasing per-stream sequence number
	FECGroup      uint32    // FEC group number (all shards in a group share this)
	FECIndex      uint8     // shard index within the group [0, FECTotal)
	FECTotal      uint8     // total shards in this group (data + parity)
	FECDataShards uint8     // number of original data shards (rest are parity)
	_             [1]byte   // reserved
	PayloadLength uint16    // byte length of the game payload following the header
}

// Packet is the fully parsed in-memory representation of a TGP datagram.
// The Outer/Inner split is used at different pipeline stages.
type Packet struct {
	Outer   OuterHeader
	Inner   InnerHeader
	Payload []byte
	// ReceivedAt is set by the receive path for jitter/RTT measurement.
	ReceivedAt time.Time
	// SourceAddr is the UDP source address; used by connection migration logic.
	SourceAddr net.Addr
}

// PacingToken is consumed by the Token Bucket pacer before each send.
// This type exists to make the pacer interface explicit.
type PacingToken struct{}

// FECGroupState accumulates shards for a single FEC group until either all
// data shards arrive (fast path) or enough shards arrive to reconstruct.
type FECGroupState struct {
	GroupID    uint32
	DataShards int
	// Shards is indexed by FECIndex. A nil entry means not yet received.
	Shards     [][]byte
	ReceivedAt time.Time
	// Recovered is true once Reed-Solomon reconstruction has been applied.
	Recovered bool
}

// ---------------------------------------------------------------------------
// State machine interfaces
// ---------------------------------------------------------------------------

// SessionState represents the lifecycle of a single TGP session.
type SessionState int

const (
	// SessionHandshaking is the initial state while the session key is being negotiated.
	SessionHandshaking SessionState = iota
	// SessionEstablished means the session is fully usable.
	SessionEstablished
	// SessionMigrating means a connection migration is in progress; packets
	// continue to flow on the old path while the new path is validated.
	SessionMigrating
	// SessionClosing is entered when a FlagClose packet has been sent or received.
	SessionClosing
	// SessionClosed is the terminal state.
	SessionClosed
)

// Session is the core state-machine interface for a single TGP session on
// both the client and server sides.
//
// All methods are safe for concurrent use.
type Session interface {
	// ID returns the immutable session identifier.
	ID() SessionID

	// State returns the current lifecycle state.
	State() SessionState

	// SendPacket transmits a game UDP payload on the given stream. The pacer
	// may delay the call to enforce token-bucket rate limiting.
	// ctx cancellation aborts the send.
	SendPacket(ctx context.Context, streamID StreamID, payload []byte) error

	// RecvPacket blocks until a reassembled game payload is available on
	// the given stream, or ctx is cancelled.
	RecvPacket(ctx context.Context, streamID StreamID) ([]byte, error)

	// Migrate initiates connection migration to newAddr. The session ID is
	// preserved; only the underlying UDP socket path changes.
	// Returns once the migration is confirmed by the peer.
	Migrate(ctx context.Context, newAddr net.Addr) error

	// Close sends a FlagClose packet and releases session resources.
	Close() error

	// Stats returns a snapshot of per-session telemetry (RTT, jitter, loss, etc.).
	Stats() SessionStats
}

// SessionStats is a point-in-time snapshot of session telemetry.
type SessionStats struct {
	RTT           time.Duration
	Jitter        time.Duration
	PacketLoss    float64 // 0.0 – 1.0
	BytesSent     uint64
	BytesReceived uint64
	FECRecovered  uint64 // packets recovered via Reed-Solomon
	Migrations    uint32 // number of successful connection migrations
}

// Pacer defines the token-bucket interface used to control packet send rate.
// Each call to Consume blocks until a token is available.
type Pacer interface {
	// Consume waits for one token. ctx cancellation unblocks the call.
	Consume(ctx context.Context) error
	// SetRate updates the token refill rate in packets-per-second.
	// Thread-safe; the new rate takes effect on the next token request.
	SetRate(pps float64)
	// Rate returns the current refill rate.
	Rate() float64
}

// FECCodec encodes and decodes Reed-Solomon FEC groups.
type FECCodec interface {
	// Encode takes up to DataShards original payloads and returns dataShards +
	// parityShards encoded shards. Each shard is the same length (zero-padded).
	Encode(data [][]byte, dataShards, parityShards int) ([][]byte, error)

	// Reconstruct recovers missing shards in-place. Callers mark missing shards
	// with a nil slice. Returns an error if reconstruction is impossible.
	Reconstruct(shards [][]byte, dataShards, parityShards int) error
}

// Transport is the lowest-level UDP send/receive interface.
// On multipath configurations, multiple Transports may be composed behind a
// MultipathTransport adapter that fans out writes to all paths simultaneously.
type Transport interface {
	// WritePacket sends a single encoded TGP packet to addr.
	WritePacket(ctx context.Context, pkt []byte, addr net.Addr) error
	// ReadPacket blocks until a packet arrives. The returned slice is owned by
	// the caller; Transport may reuse the buffer on the next call.
	ReadPacket(ctx context.Context) (pkt []byte, from net.Addr, err error)
	// LocalAddr returns the local UDP address.
	LocalAddr() net.Addr
	// Close releases the underlying socket.
	Close() error
}

// Server is the TGP server-side session manager.
type Server interface {
	// Accept blocks until a new TGP session handshake is received, then returns
	// a newly established Session.
	Accept(ctx context.Context) (Session, error)
	// Close shuts down the server and all active sessions.
	Close() error
}
