package tgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	fecLengthPrefixSize       = 2
	MaxFECDataShards          = 32
	MaxFECParityShards        = 16
	MaxFECTotalShards         = MaxFECDataShards + MaxFECParityShards
	MaxFECReceiveGroups       = 64
	MaxFECCompletedGroups     = 4096
	MaxFECReceiveBufferedByte = 4 << 20
	fecReceiveGroupLifetime   = 30 * time.Second
)

var (
	ErrInvalidFECParams = errors.New("invalid fec parameters")
	ErrFECResourceLimit = errors.New("fec receive resource limit exceeded")
	ErrFECShardTooLarge = errors.New("fec shard exceeds protocol limit")
)

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
		if len(shard)+fecLengthPrefixSize > maxTGPDataPayloadSize {
			return nil, fmt.Errorf("%w: %d > %d", ErrFECShardTooLarge, len(shard)+fecLengthPrefixSize, maxTGPDataPayloadSize)
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
	for _, shard := range shards {
		if len(shard) > maxTGPDataPayloadSize {
			return fmt.Errorf("%w: %d > %d", ErrFECShardTooLarge, len(shard), maxTGPDataPayloadSize)
		}
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
	if dataShards > MaxFECDataShards {
		return fmt.Errorf("%w: data shards %d exceed %d", ErrInvalidFECParams, dataShards, MaxFECDataShards)
	}
	if parityShards > MaxFECParityShards {
		return fmt.Errorf("%w: parity shards %d exceed %d", ErrInvalidFECParams, parityShards, MaxFECParityShards)
	}
	if dataShards+parityShards > MaxFECTotalShards {
		return fmt.Errorf("%w: total shards %d exceed %d", ErrInvalidFECParams, dataShards+parityShards, MaxFECTotalShards)
	}
	return nil
}

func validateFECOptions(options FECOptions) error {
	if options.DataShards == 0 && options.ParityShards == 0 {
		return nil
	}
	if options.DataShards < 1 || options.DataShards > MaxFECDataShards {
		return fmt.Errorf("%w: data shards %d must be between 1 and %d", ErrInvalidFECParams, options.DataShards, MaxFECDataShards)
	}
	if options.ParityShards < 0 || options.ParityShards > MaxFECParityShards {
		return fmt.Errorf("%w: parity shards %d must be between 0 and %d", ErrInvalidFECParams, options.ParityShards, MaxFECParityShards)
	}
	if options.ParityShards > 0 {
		if err := validateFECParams(options.DataShards, options.ParityShards); err != nil {
			return err
		}
	}
	if options.MaxReceiveGroups < 0 || options.MaxReceiveGroups > MaxFECReceiveGroups {
		return fmt.Errorf("%w: receive groups %d must be between 0 and %d", ErrInvalidFECParams, options.MaxReceiveGroups, MaxFECReceiveGroups)
	}
	return nil
}

type FECReceiveResult struct {
	Payloads        [][]byte
	Ready           bool
	RecoveredShards int
}

type FECReceiveBuffer struct {
	codec            FECCodec
	groups           map[uint32]*FECGroupState
	completedGroups  map[uint32]time.Time
	maxGroups        int
	maxBufferedBytes int
	bufferedBytes    int
}

func NewFECReceiveBuffer(codec FECCodec, maxGroups int) *FECReceiveBuffer {
	if codec == nil {
		codec = NewReedSolomonCodec()
	}
	if maxGroups <= 0 {
		maxGroups = MaxFECReceiveGroups
	}
	if maxGroups > MaxFECReceiveGroups {
		maxGroups = MaxFECReceiveGroups
	}
	return &FECReceiveBuffer{
		codec:            codec,
		groups:           make(map[uint32]*FECGroupState),
		completedGroups:  make(map[uint32]time.Time),
		maxGroups:        maxGroups,
		maxBufferedBytes: MaxFECReceiveBufferedByte,
	}
}

func (b *FECReceiveBuffer) AddPacket(packet Packet) (FECReceiveResult, error) {
	header := packet.Inner
	if header.FECTotal == 0 || header.FECDataShards == 0 {
		if len(packet.Payload) > maxTGPDataPayloadSize {
			return FECReceiveResult{}, fmt.Errorf("%w: %d > %d", ErrFECShardTooLarge, len(packet.Payload), maxTGPDataPayloadSize)
		}
		return FECReceiveResult{
			Payloads: [][]byte{append([]byte(nil), packet.Payload...)},
			Ready:    true,
		}, nil
	}
	if header.FECDataShards >= header.FECTotal {
		return FECReceiveResult{}, fmt.Errorf("%w: fec data shards must be smaller than total shards", ErrInvalidFECParams)
	}
	dataShards := int(header.FECDataShards)
	parityShards := int(header.FECTotal) - dataShards
	if err := validateFECParams(dataShards, parityShards); err != nil {
		return FECReceiveResult{}, err
	}
	if len(packet.Payload) > maxTGPDataPayloadSize {
		return FECReceiveResult{}, fmt.Errorf("%w: %d > %d", ErrFECShardTooLarge, len(packet.Payload), maxTGPDataPayloadSize)
	}
	if header.FECIndex >= header.FECTotal {
		return FECReceiveResult{}, fmt.Errorf("%w: fec index %d exceeds total %d", ErrInvalidFECParams, header.FECIndex, header.FECTotal)
	}
	if b == nil {
		b = NewFECReceiveBuffer(nil, 0)
	}

	b.purgeExpiredGroups(time.Now())
	if _, completed := b.completedGroups[header.FECGroup]; completed {
		return FECReceiveResult{}, nil
	}
	group, err := b.group(header)
	if err != nil {
		return FECReceiveResult{}, err
	}
	if group.DataShards != int(header.FECDataShards) || len(group.Shards) != int(header.FECTotal) {
		return FECReceiveResult{}, fmt.Errorf("%w: inconsistent fec group metadata", ErrInvalidFECParams)
	}

	index := int(header.FECIndex)
	if group.Shards[index] != nil {
		return FECReceiveResult{}, nil
	}
	if b.bufferedBytes+len(packet.Payload) > b.maxBufferedBytes {
		return FECReceiveResult{}, fmt.Errorf("%w: buffered bytes %d + shard %d > %d", ErrFECResourceLimit, b.bufferedBytes, len(packet.Payload), b.maxBufferedBytes)
	}
	group.Shards[index] = append([]byte(nil), packet.Payload...)
	b.bufferedBytes += len(packet.Payload)

	if index < group.DataShards && header.Flags&FlagFEC == 0 {
		payload, err := decodeFECDataShard(group.Shards[index])
		if err != nil {
			return FECReceiveResult{}, err
		}
		if group.Delivered[index] {
			return FECReceiveResult{}, nil
		}
		group.Delivered[index] = true
		result := FECReceiveResult{
			Payloads: [][]byte{payload},
			Ready:    true,
		}
		b.completeGroupIfDelivered(group)
		return result, nil
	}

	if !hasEnoughFECShards(group) {
		return FECReceiveResult{}, nil
	}

	missing := missingDataShardIndexes(group)
	if len(missing) == 0 {
		return FECReceiveResult{}, nil
	}
	groupDataShards := group.DataShards
	groupParityShards := len(group.Shards) - groupDataShards
	if err := b.codec.Reconstruct(group.Shards, groupDataShards, groupParityShards); err != nil {
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
	b.completeGroupIfDelivered(group)
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

func (b *FECReceiveBuffer) BufferedBytes() int {
	if b == nil {
		return 0
	}
	return b.bufferedBytes
}

func (b *FECReceiveBuffer) group(header InnerHeader) (*FECGroupState, error) {
	group, ok := b.groups[header.FECGroup]
	if ok {
		return group, nil
	}
	if len(b.groups) >= b.maxGroups {
		return nil, fmt.Errorf("%w: groups %d >= %d", ErrFECResourceLimit, len(b.groups), b.maxGroups)
	}
	group = &FECGroupState{
		GroupID:    header.FECGroup,
		DataShards: int(header.FECDataShards),
		Shards:     make([][]byte, int(header.FECTotal)),
		Delivered:  make([]bool, int(header.FECDataShards)),
		ReceivedAt: time.Now(),
	}
	b.groups[header.FECGroup] = group
	return group, nil
}

func (b *FECReceiveBuffer) completeGroupIfDelivered(group *FECGroupState) {
	for _, delivered := range group.Delivered {
		if !delivered {
			return
		}
	}
	b.releaseGroupShards(group)
	delete(b.groups, group.GroupID)
	b.rememberCompletedGroup(group.GroupID, time.Now())
}

func (b *FECReceiveBuffer) purgeExpiredGroups(now time.Time) {
	for id, group := range b.groups {
		if now.Sub(group.ReceivedAt) >= fecReceiveGroupLifetime {
			b.releaseGroupShards(group)
			delete(b.groups, id)
		}
	}
	for id, completedAt := range b.completedGroups {
		if now.Sub(completedAt) >= fecReceiveGroupLifetime {
			delete(b.completedGroups, id)
		}
	}
}

func (b *FECReceiveBuffer) rememberCompletedGroup(id uint32, completedAt time.Time) {
	if len(b.completedGroups) >= MaxFECCompletedGroups {
		var oldestID uint32
		var oldestAt time.Time
		first := true
		for candidateID, candidateAt := range b.completedGroups {
			if first || candidateAt.Before(oldestAt) {
				oldestID = candidateID
				oldestAt = candidateAt
				first = false
			}
		}
		delete(b.completedGroups, oldestID)
	}
	b.completedGroups[id] = completedAt
}

func (b *FECReceiveBuffer) releaseGroupShards(group *FECGroupState) {
	for index, shard := range group.Shards {
		b.bufferedBytes -= len(shard)
		group.Shards[index] = nil
	}
	if b.bufferedBytes < 0 {
		b.bufferedBytes = 0
	}
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
	if len(payload)+fecLengthPrefixSize > maxTGPDataPayloadSize || shardSize > maxTGPDataPayloadSize {
		return nil, fmt.Errorf("%w: shard size %d exceeds %d", ErrFECShardTooLarge, shardSize, maxTGPDataPayloadSize)
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
