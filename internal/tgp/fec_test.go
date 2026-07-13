package tgp

import (
	"bytes"
	"errors"
	"testing"
	"time"
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

func TestFECReceiveBufferReconstructsWithUnpaddedDataShard(t *testing.T) {
	codec := NewReedSolomonCodec()
	data := [][]byte{
		[]byte("a"),
		[]byte("second payload is longer"),
	}
	shards, err := codec.Encode(data, 2, 1)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	shortFirstShard, err := frameFECData(data[0], len(data[0])+fecLengthPrefixSize)
	if err != nil {
		t.Fatalf("frame short shard: %v", err)
	}

	buffer := NewFECReceiveBuffer(codec, 0)
	if result, err := buffer.AddPacket(fecPacket(31, 0, 3, 2, shortFirstShard)); err != nil || !result.Ready {
		t.Fatalf("short data shard ready=%v err=%v", result.Ready, err)
	}
	result, err := buffer.AddPacket(fecPacket(31, 2, 3, 2, shards[2]))
	if err != nil {
		t.Fatalf("parity shard: %v", err)
	}
	if !result.Ready || result.RecoveredShards != 1 {
		t.Fatalf("expected one recovered shard: %#v", result)
	}
	if !bytes.Equal(result.Payloads[0], data[1]) {
		t.Fatalf("recovered payload mismatch: %q != %q", result.Payloads[0], data[1])
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

func TestFECReceiveBufferDoesNotDeliverFECOnlyDataShard(t *testing.T) {
	codec := NewReedSolomonCodec()
	data := [][]byte{[]byte("alpha"), nil}
	shards, err := codec.Encode(data, 2, 1)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	buffer := NewFECReceiveBuffer(codec, 0)
	result, err := buffer.AddPacket(fecPacketWithFlags(41, 1, 3, 2, shards[1], FlagFEC))
	if err != nil {
		t.Fatalf("add fec-only data shard: %v", err)
	}
	if result.Ready || len(result.Payloads) != 0 {
		t.Fatalf("fec-only data shard was delivered: %#v", result)
	}
}

func TestFECRejectsShardCountsAboveProtocolLimit(t *testing.T) {
	codec := NewReedSolomonCodec()
	if _, err := codec.Encode(nil, MaxFECDataShards+1, 1); !errors.Is(err, ErrInvalidFECParams) {
		t.Fatalf("data shard limit error = %v", err)
	}
	if _, err := codec.Encode(nil, 1, MaxFECParityShards+1); !errors.Is(err, ErrInvalidFECParams) {
		t.Fatalf("parity shard limit error = %v", err)
	}
	buffer := NewFECReceiveBuffer(codec, 0)
	packet := fecPacket(1, 0, 255, 1, []byte{0, 0})
	if _, err := buffer.AddPacket(packet); !errors.Is(err, ErrInvalidFECParams) {
		t.Fatalf("wire shard count error = %v, want %v", err, ErrInvalidFECParams)
	}
	if buffer.PendingGroups() != 0 || buffer.BufferedBytes() != 0 {
		t.Fatalf("invalid shard counts allocated state: groups=%d bytes=%d", buffer.PendingGroups(), buffer.BufferedBytes())
	}
}

func TestFECRejectsOversizedShardBeforeBuffering(t *testing.T) {
	codec := NewReedSolomonCodec()
	if _, err := codec.Encode([][]byte{make([]byte, maxTGPDataPayloadSize)}, 1, 1); !errors.Is(err, ErrFECShardTooLarge) {
		t.Fatalf("encode oversized shard error = %v", err)
	}
	buffer := NewFECReceiveBuffer(codec, 0)
	packet := fecPacket(2, 0, 2, 1, make([]byte, maxTGPDataPayloadSize+1))
	if _, err := buffer.AddPacket(packet); !errors.Is(err, ErrFECShardTooLarge) {
		t.Fatalf("receive oversized shard error = %v", err)
	}
	if buffer.PendingGroups() != 0 || buffer.BufferedBytes() != 0 {
		t.Fatalf("oversized shard allocated state: groups=%d bytes=%d", buffer.PendingGroups(), buffer.BufferedBytes())
	}
}

func TestFECReceiveBufferFailsClosedAtGroupLimit(t *testing.T) {
	buffer := NewFECReceiveBuffer(nil, 1)
	first := fecPacketWithFlags(10, 2, 3, 2, []byte{1, 2, 3}, FlagFEC)
	if _, err := buffer.AddPacket(first); err != nil {
		t.Fatal(err)
	}
	second := fecPacketWithFlags(11, 2, 3, 2, []byte{4, 5, 6}, FlagFEC)
	if _, err := buffer.AddPacket(second); !errors.Is(err, ErrFECResourceLimit) {
		t.Fatalf("group limit error = %v, want %v", err, ErrFECResourceLimit)
	}
	if buffer.PendingGroups() != 1 || buffer.BufferedBytes() != len(first.Payload) {
		t.Fatalf("group limit mutated state: groups=%d bytes=%d", buffer.PendingGroups(), buffer.BufferedBytes())
	}
}

func TestFECReceiveBufferFailsClosedAtByteLimit(t *testing.T) {
	buffer := NewFECReceiveBuffer(nil, 2)
	buffer.maxBufferedBytes = 5
	first := fecPacketWithFlags(20, 2, 3, 2, []byte{1, 2, 3, 4}, FlagFEC)
	if _, err := buffer.AddPacket(first); err != nil {
		t.Fatal(err)
	}
	second := fecPacket(20, 0, 3, 2, []byte{0, 0, 5, 6})
	if _, err := buffer.AddPacket(second); !errors.Is(err, ErrFECResourceLimit) {
		t.Fatalf("byte limit error = %v, want %v", err, ErrFECResourceLimit)
	}
	if buffer.BufferedBytes() != len(first.Payload) {
		t.Fatalf("byte limit mutated buffer: got %d want %d", buffer.BufferedBytes(), len(first.Payload))
	}
}

func TestFECCompletedGroupsDoNotConsumeActiveGroupCapacity(t *testing.T) {
	buffer := NewFECReceiveBuffer(nil, 1)
	for group := uint32(1); group <= 100; group++ {
		result, err := buffer.AddPacket(fecPacket(group, 0, 2, 1, []byte{0, 0}))
		if err != nil {
			t.Fatalf("complete group %d: %v", group, err)
		}
		if !result.Ready {
			t.Fatalf("complete group %d was not delivered", group)
		}
	}
	if buffer.PendingGroups() != 0 || buffer.BufferedBytes() != 0 {
		t.Fatalf("completed groups retained payload state: groups=%d bytes=%d", buffer.PendingGroups(), buffer.BufferedBytes())
	}
}

func TestFECCompletedGroupMaintenanceIsAmortizedConstantTime(t *testing.T) {
	buffer := NewFECReceiveBuffer(nil, 1)
	completedAt := time.Unix(1_700_000_000, 0)
	for id := uint32(0); id < MaxFECCompletedGroups; id++ {
		buffer.rememberCompletedGroup(id, completedAt)
	}

	before := buffer.completedMaintenanceOps
	const packets = 10_000
	for range packets {
		buffer.purgeExpiredGroups(completedAt.Add(time.Second))
	}
	work := buffer.completedMaintenanceOps - before
	if work > packets {
		t.Fatalf("completed tombstone maintenance operations = %d for %d packets, want <= %d", work, packets, packets)
	}
	if len(buffer.completedGroups) != MaxFECCompletedGroups {
		t.Fatalf("completed tombstones = %d, want %d", len(buffer.completedGroups), MaxFECCompletedGroups)
	}

	buffer.rememberCompletedGroup(MaxFECCompletedGroups, completedAt.Add(2*time.Second))
	if len(buffer.completedGroups) != MaxFECCompletedGroups {
		t.Fatalf("bounded completed tombstones = %d, want %d", len(buffer.completedGroups), MaxFECCompletedGroups)
	}
	if _, retained := buffer.completedGroups[0]; retained {
		t.Fatal("oldest completed tombstone was not evicted in O(1)")
	}
	if _, retained := buffer.completedGroups[MaxFECCompletedGroups]; !retained {
		t.Fatal("new completed tombstone was not retained")
	}
}

func fecPacket(group uint32, index int, total int, dataShards int, payload []byte) Packet {
	return fecPacketWithFlags(group, index, total, dataShards, payload, 0)
}

func fecPacketWithFlags(group uint32, index int, total int, dataShards int, payload []byte, flags uint8) Packet {
	return Packet{
		Inner: InnerHeader{
			Flags:         flags,
			FECGroup:      group,
			FECIndex:      uint8(index),
			FECTotal:      uint8(total),
			FECDataShards: uint8(dataShards),
		},
		Payload: payload,
	}
}
