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
	shards[2] = nil

	if err := codec.Reconstruct(shards, 4, 2); err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	payload, err := decodeFECDataShard(shards[2])
	if err != nil {
		t.Fatalf("decode reconstructed shard: %v", err)
	}
	if !bytes.Equal(payload, data[2]) {
		t.Fatalf("reconstructed shard mismatch: %q != %q", payload, data[2])
	}
}

func TestFECReceiveBufferPassesThroughNonFEC(t *testing.T) {
	buffer := NewFECReceiveBuffer(nil, 0)
	result, err := buffer.AddPacket(Packet{
		Inner:   InnerHeader{},
		Payload: []byte("plain datagram"),
	})
	if err != nil {
		t.Fatalf("add packet: %v", err)
	}
	if !result.Ready {
		t.Fatal("non-FEC packet should be ready")
	}
	if len(result.Payloads) != 1 || !bytes.Equal(result.Payloads[0], []byte("plain datagram")) {
		t.Fatalf("unexpected payloads: %q", result.Payloads)
	}
}

func TestFECReceiveBufferDeliversDataShardImmediately(t *testing.T) {
	codec := NewReedSolomonCodec()
	data := [][]byte{[]byte("alpha"), []byte("bravo")}
	shards, err := codec.Encode(data, 2, 1)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	buffer := NewFECReceiveBuffer(codec, 0)
	result, err := buffer.AddPacket(fecPacket(9, 0, 3, 2, shards[0]))
	if err != nil {
		t.Fatalf("add data shard: %v", err)
	}
	if !result.Ready || len(result.Payloads) != 1 {
		t.Fatalf("data shard should be delivered immediately: %#v", result)
	}
	if !bytes.Equal(result.Payloads[0], data[0]) {
		t.Fatalf("payload mismatch: %q != %q", result.Payloads[0], data[0])
	}
}

func TestFECReceiveBufferReconstructsMissingDataShard(t *testing.T) {
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
	buffer := NewFECReceiveBuffer(codec, 0)

	for _, index := range []int{0, 1, 3} {
		result, err := buffer.AddPacket(fecPacket(17, index, 6, 4, shards[index]))
		if err != nil {
			t.Fatalf("add data shard %d: %v", index, err)
		}
		if !result.Ready || len(result.Payloads) != 1 {
			t.Fatalf("data shard %d not delivered immediately: %#v", index, result)
		}
	}

	result, err := buffer.AddPacket(fecPacket(17, 4, 6, 4, shards[4]))
	if err != nil {
		t.Fatalf("add parity shard: %v", err)
	}
	if !result.Ready {
		t.Fatal("expected parity shard to recover missing data")
	}
	if result.RecoveredShards != 1 {
		t.Fatalf("expected one recovered shard, got %d", result.RecoveredShards)
	}
	if len(result.Payloads) != 1 || !bytes.Equal(result.Payloads[0], data[2]) {
		t.Fatalf("unexpected recovered payloads: %q", result.Payloads)
	}
}

func TestFECReceiveBufferSuppressesDuplicateAndLateRecoveredShard(t *testing.T) {
	codec := NewReedSolomonCodec()
	data := [][]byte{
		[]byte("alpha"),
		[]byte("bravo"),
	}
	shards, err := codec.Encode(data, 2, 1)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	buffer := NewFECReceiveBuffer(codec, 0)

	if result, err := buffer.AddPacket(fecPacket(9, 0, 3, 2, shards[0])); err != nil || !result.Ready {
		t.Fatalf("first shard ready=%v err=%v", result.Ready, err)
	}
	if result, err := buffer.AddPacket(fecPacket(9, 0, 3, 2, shards[0])); err != nil || result.Ready {
		t.Fatalf("duplicate shard ready=%v err=%v", result.Ready, err)
	}
	result, err := buffer.AddPacket(fecPacket(9, 2, 3, 2, shards[2]))
	if err != nil {
		t.Fatalf("parity shard: %v", err)
	}
	if !result.Ready || result.RecoveredShards != 1 || !bytes.Equal(result.Payloads[0], data[1]) {
		t.Fatalf("unexpected recovery result: %#v", result)
	}
	if result, err := buffer.AddPacket(fecPacket(9, 1, 3, 2, shards[1])); err != nil || result.Ready {
		t.Fatalf("late original shard should be suppressed ready=%v err=%v", result.Ready, err)
	}
}

func fecPacket(group uint32, index int, total int, dataShards int, payload []byte) Packet {
	return Packet{
		Inner: InnerHeader{
			FECGroup:      group,
			FECIndex:      uint8(index),
			FECTotal:      uint8(total),
			FECDataShards: uint8(dataShards),
		},
		Payload: payload,
	}
}
