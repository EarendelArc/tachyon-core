package protocol

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	Magic   uint32 = 0x54475031
	Version uint8  = 1
)

type CID [16]byte

type PacketType uint8

const (
	PacketInitial PacketType = 1
	PacketData    PacketType = 2
	PacketPath    PacketType = 3
	PacketClose   PacketType = 4
)

type FECMeta struct {
	GroupID      uint32
	ShardID      uint8
	DataShards   uint8
	ParityShards uint8
	OriginalLen  uint16
}

type Header struct {
	Magic       uint32
	Version     uint8
	Type        PacketType
	Flags       uint16
	CID         CID
	PacketNo    uint64
	PathID      uint32
	TimestampUS uint64
	FEC         FECMeta
	Nonce       [12]byte
}

type Packet struct {
	Header  Header
	Payload []byte
	Tag     [16]byte
}

func (h Header) Validate() error {
	if h.Magic != Magic {
		return errors.New("invalid tgp magic")
	}
	if h.Version != Version {
		return errors.New("unsupported tgp version")
	}
	if h.Type < PacketInitial || h.Type > PacketClose {
		return errors.New("invalid tgp packet type")
	}
	return nil
}

type SessionState uint8

const (
	StateIdle SessionState = iota
	StateHandshaking
	StateActive
	StateMigrating
	StateDraining
	StateClosed
)

type PathInfo struct {
	ID        uint32
	Local     net.Addr
	Remote    net.Addr
	RTT       time.Duration
	LossRate  float64
	Available bool
}

type SessionStats struct {
	RTT        time.Duration
	Jitter     time.Duration
	LossRate   float64
	SendRate   uint64
	RecvRate   uint64
	Recovered  uint64
	Duplicated uint64
}

type StateMachine interface {
	CID() CID
	State() SessionState
	Open(ctx context.Context) error
	HandlePacket(ctx context.Context, pkt Packet) error
	SendDatagram(ctx context.Context, payload []byte) error
	AddPath(ctx context.Context, path PathInfo) error
	Migrate(ctx context.Context, pathID uint32) error
	Close(ctx context.Context, reason string) error
	Stats() SessionStats
}
