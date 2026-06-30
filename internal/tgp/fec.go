package tgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/klauspost/reedsolomon"
)

const fecLengthPrefixSize = 2

var ErrInvalidFECParams = errors.New("invalid fec parameters")

type ReedSolomonCodec struct{}

func NewReedSolomonCodec() *ReedSolomonCodec {
	return &ReedSolomonCodec{}
}

func (c *ReedSolomonCodec) Encode(data [][]byte, dataShards, parityShards int) ([][]byte, error) {
	if err := validateFECParams(dataShards, parityShards); err != nil {
		return nil, err
	}
	if len(data) > dataShards {
		return nil, fmt.Errorf("%w: got %d data shards, capacity %d", ErrInvalidFECParams, len(data), dataShards)
	}

	shardSize := fecLengthPrefixSize
	for _, shard := range data {
		if len(shard) > 0xffff {
			return nil, fmt.Errorf("%w: data shard exceeds 65535 bytes", ErrInvalidFECParams)
		}
		if len(shard)+fecLengthPrefixSize > shardSize {
			shardSize = len(shard) + fecLengthPrefixSize
		}
	}

	total := dataShards + parityShards
	shards := make([][]byte, total)
	for i := 0; i < dataShards; i++ {
		var payload []byte
		if i < len(data) {
			payload = data[i]
		}
		shard, err := frameFECData(payload, shardSize)
		if err != nil {
			return nil, err
		}
		shards[i] = shard
	}
	for i := dataShards; i < total; i++ {
		shards[i] = make([]byte, shardSize)
	}

	encoder, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("create reed-solomon encoder: %w", err)
	}
	if err := encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("encode fec shards: %w", err)
	}
	return shards, nil
}

func (c *ReedSolomonCodec) Reconstruct(shards [][]byte, dataShards, parityShards int) error {
	if err := validateFECParams(dataShards, parityShards); err != nil {
		return err
	}
	if len(shards) != dataShards+parityShards {
		return fmt.Errorf("%w: shard count %d does not match data+parity %d", ErrInvalidFECParams, len(shards), dataShards+parityShards)
	}
	normalizeFECShardLengths(shards)

	encoder, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return fmt.Errorf("create reed-solomon encoder: %w", err)
	}
	if err := encoder.Reconstruct(shards); err != nil {
		return fmt.Errorf("reconstruct fec shards: %w", err)
	}
	ok, err := encoder.Verify(shards)
	if err != nil {
		return fmt.Errorf("verify fec shards: %w", err)
	}
	if !ok {
		return errors.New("fec reconstruction verification failed")
	}
	return nil
}

func validateFECParams(dataShards, parityShards int) error {
	if dataShards < 1 || parityShards < 1 {
		return fmt.Errorf("%w: data and parity shards must be positive", ErrInvalidFECParams)
	}
	return nil
}

type FECReceiveResult struct {
	Payloads        [][]byte
	Ready           bool
	RecoveredShards int
}

type FECReceiveBuffer struct {
	codec     FECCodec
	groups    map[uint32]*FECGroupState
	maxGroups int
}

func NewFECReceiveBuffer(codec FECCodec, maxGroups int) *FECReceiveBuffer {
	if codec == nil {
		codec = NewReedSolomonCodec()
	}
	if maxGroups <= 0 {
		maxGroups = 128
	}
	return &FECReceiveBuffer{
		codec:     codec,
		groups:    make(map[uint32]*FECGroupState),
		maxGroups: maxGroups,
	}
}

func (b *FECReceiveBuffer) AddPacket(packet Packet) (FECReceiveResult, error) {
	header := packet.Inner
	if header.FECTotal == 0 || header.FECDataShards == 0 {
		return FECReceiveResult{
			Payloads: [][]byte{append([]byte(nil), packet.Payload...)},
			Ready:    true,
		}, nil
	}
	if header.FECDataShards >= header.FECTotal {
		return FECReceiveResult{}, fmt.Errorf("%w: fec data shards must be smaller than total shards", ErrInvalidFECParams)
	}
	if header.FECIndex >= header.FECTotal {
		return FECReceiveResult{}, fmt.Errorf("%w: fec index %d exceeds total %d", ErrInvalidFECParams, header.FECIndex, header.FECTotal)
	}
	if b == nil {
		b = NewFECReceiveBuffer(nil, 0)
	}

	group := b.group(header)
	if group.DataShards != int(header.FECDataShards) || len(group.Shards) != int(header.FECTotal) {
		return FECReceiveResult{}, fmt.Errorf("%w: inconsistent fec group metadata", ErrInvalidFECParams)
	}

	index := int(header.FECIndex)
	if group.Shards[index] != nil {
		return FECReceiveResult{}, nil
	}
	group.Shards[index] = append([]byte(nil), packet.Payload...)

	if index < group.DataShards {
		payload, err := decodeFECDataShard(group.Shards[index])
		if err != nil {
			return FECReceiveResult{}, err
		}
		if group.Delivered[index] {
			return FECReceiveResult{}, nil
		}
		group.Delivered[index] = true
		return FECReceiveResult{
			Payloads: [][]byte{payload},
			Ready:    true,
		}, nil
	}

	if !hasEnoughFECShards(group) {
		return FECReceiveResult{}, nil
	}

	missing := missingDataShardIndexes(group)
	if len(missing) == 0 {
		return FECReceiveResult{}, nil
	}
	dataShards := group.DataShards
	parityShards := len(group.Shards) - dataShards
	if err := b.codec.Reconstruct(group.Shards, dataShards, parityShards); err != nil {
		return FECReceiveResult{}, err
	}
	group.Recovered = true

	payloads := make([][]byte, 0, len(missing))
	for _, missingIndex := range missing {
		payload, err := decodeFECDataShard(group.Shards[missingIndex])
		if err != nil {
			return FECReceiveResult{}, err
		}
		group.Delivered[missingIndex] = true
		payloads = append(payloads, payload)
	}
	return FECReceiveResult{
		Payloads:        payloads,
		Ready:           len(payloads) > 0,
		RecoveredShards: len(payloads),
	}, nil
}

func (b *FECReceiveBuffer) PendingGroups() int {
	if b == nil {
		return 0
	}
	return len(b.groups)
}

func (b *FECReceiveBuffer) group(header InnerHeader) *FECGroupState {
	group, ok := b.groups[header.FECGroup]
	if ok {
		return group
	}
	if len(b.groups) >= b.maxGroups {
		var oldestID uint32
		var oldestAt time.Time
		first := true
		for id, candidate := range b.groups {
			if first || candidate.ReceivedAt.Before(oldestAt) {
				oldestID = id
				oldestAt = candidate.ReceivedAt
				first = false
			}
		}
		delete(b.groups, oldestID)
	}
	group = &FECGroupState{
		GroupID:    header.FECGroup,
		DataShards: int(header.FECDataShards),
		Shards:     make([][]byte, int(header.FECTotal)),
		Delivered:  make([]bool, int(header.FECDataShards)),
		ReceivedAt: time.Now(),
	}
	b.groups[header.FECGroup] = group
	return group
}

func hasEnoughFECShards(group *FECGroupState) bool {
	received := 0
	for _, shard := range group.Shards {
		if shard != nil {
			received++
		}
	}
	return received >= group.DataShards
}

func missingDataShardIndexes(group *FECGroupState) []int {
	missing := make([]int, 0, group.DataShards)
	for i := 0; i < group.DataShards; i++ {
		if group.Shards[i] == nil {
			missing = append(missing, i)
		}
	}
	return missing
}

func frameFECData(payload []byte, shardSize int) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("%w: data shard exceeds 65535 bytes", ErrInvalidFECParams)
	}
	if shardSize < len(payload)+fecLengthPrefixSize {
		return nil, fmt.Errorf("%w: fec shard size too small", ErrInvalidFECParams)
	}
	shard := make([]byte, shardSize)
	binary.BigEndian.PutUint16(shard[:fecLengthPrefixSize], uint16(len(payload)))
	copy(shard[fecLengthPrefixSize:], payload)
	return shard, nil
}

func decodeFECDataShard(shard []byte) ([]byte, error) {
	if len(shard) < fecLengthPrefixSize {
		return nil, fmt.Errorf("%w: fec data shard too short", ErrInvalidFECParams)
	}
	payloadLen := int(binary.BigEndian.Uint16(shard[:fecLengthPrefixSize]))
	if payloadLen > len(shard)-fecLengthPrefixSize {
		return nil, fmt.Errorf("%w: fec data shard length exceeds payload", ErrInvalidFECParams)
	}
	payload := shard[fecLengthPrefixSize : fecLengthPrefixSize+payloadLen]
	return append([]byte(nil), payload...), nil
}

func normalizeFECShardLengths(shards [][]byte) {
	maxSize := 0
	for _, shard := range shards {
		if len(shard) > maxSize {
			maxSize = len(shard)
		}
	}
	for i, shard := range shards {
		if shard == nil || len(shard) == maxSize {
			continue
		}
		padded := make([]byte, maxSize)
		copy(padded, shard)
		shards[i] = padded
	}
}

var _ FECCodec = (*ReedSolomonCodec)(nil)
