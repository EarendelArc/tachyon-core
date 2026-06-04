package tgp

import (
	"bytes"
	"testing"
)

func TestReedSolomonCodecReconstructsMissingShard(t *testing.T) {
	codec := NewReedSolomonCodec()
	data := [][]byte{
		[]byte("alpha"),
		[]byte("bravo"),
		[]byte("charlie"),
		[]byte("delta"),
	}

	shards, err := codec.Encode(data, 4, 2)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	original := append([]byte(nil), shards[2]...)
	shards[2] = nil

	if err := codec.Reconstruct(shards, 4, 2); err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(shards[2], original) {
		t.Fatalf("reconstructed shard mismatch: %q != %q", shards[2], original)
	}
}
