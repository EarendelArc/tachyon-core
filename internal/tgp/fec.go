package tgp

import (
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

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

	shardSize := 1
	for _, shard := range data {
		if len(shard) > shardSize {
			shardSize = len(shard)
		}
	}

	total := dataShards + parityShards
	shards := make([][]byte, total)
	for i := 0; i < dataShards; i++ {
		shards[i] = make([]byte, shardSize)
		if i < len(data) {
			copy(shards[i], data[i])
		}
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

var _ FECCodec = (*ReedSolomonCodec)(nil)
