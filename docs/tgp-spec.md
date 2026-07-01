# Tachyon Game Protocol (TGP) - Wire Format Specification

[Chinese](tgp-spec.zh-CN.md)

**Version:** TGP/1.0

**Status:** Draft

**Target audience:** Tachyon Core implementers

**Implementation status:** Core currently implements X25519/HKDF traffic-key
derivation, ChaCha20-Poly1305 packet sealing/opening, Reed-Solomon FEC codec
primitives, receive-side FEC recovery in the live session path, token-bucket
pacing, UDP session handshake, client/relay session plumbing, authenticated
source-address migration, send-side systematic FEC parity generation,
low-traffic FEC timeout flush, conservative dynamic FEC ratio adjustment, and
a sliding receive-side packet deduplication window in `internal/tgp`. Core also
includes a `MultipathTransport` adapter that fans out writes across multiple
underlying transports and merges reads from any path. Migration confirmation
control packets and explicit peer loss feedback are planned next.

---

## 1. Goals

TGP is a purpose-built UDP transport protocol for latency-sensitive game
traffic. Its design goal is not bulk throughput; it is stable pacing, low queue
depth, fast loss recovery, and connection continuity when the client path
changes.

| Goal | Mechanism |
| --- | --- |
| Low jitter | Token-bucket pacing with no burst accumulation |
| 0-RTT loss recovery | Reed-Solomon FEC |
| Connection migration | 128-bit Session ID |
| DPI resistance | DTLS-like outer header plus ChaCha20-Poly1305 |
| Multipath readiness | Multi-transport fan-out plus receive-side packet-number deduplication |

---

## 2. Packet Structure

All integer fields are encoded in big-endian order.

### 2.1 Outer Header

The plaintext outer header mimics a DTLS 1.0 application-data record:

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+-------------------------------+
| ContentType   | Version       | Epoch                         |
+---------------+---------------+-------------------------------+
| SequenceNumber (48 bits)                                      |
+---------------------------------------------------------------+
| Length                                                        |
+---------------------------------------------------------------+
```

| Field | Size | Value |
| --- | ---: | --- |
| ContentType | 1 byte | `0x17` application data |
| Version | 2 bytes | `0xFE 0xFF` DTLS 1.0 |
| Epoch | 2 bytes | `0x0000` initially |
| SequenceNumber | 6 bytes | DTLS-style packet sequence |
| Length | 2 bytes | Encrypted inner payload length |

The outer header is used as AEAD additional authenticated data. Tampering with
it causes packet open to fail.

### 2.2 Inner Header

The inner header and payload are encrypted with ChaCha20-Poly1305. Traffic
keys are derived with:

```text
HKDF-SHA256(shared_secret, salt=session_id, info="tachyon-tgp-v1 traffic keys")
```

```text
+---------------------------------------------------------------+
| Magic: 0x54 0x47 0x50 0x01 ("TGP\x01")                       |
+---------------+-----------------------------------------------+
| Flags         | Reserved                                      |
+---------------------------------------------------------------+
| SessionID (16 bytes)                                          |
+---------------+-----------------------------------------------+
| StreamID      | PacketNumber (64 bits)                        |
+---------------+---------------+---------------+---------------+
| FECGroup      | FECIndex      | FECTotal      | FECDataShards |
+---------------+---------------+---------------+---------------+
| Reserved      | PayloadLength                                 |
+---------------------------------------------------------------+
```

| Field | Size | Description |
| --- | ---: | --- |
| Magic | 4 bytes | `TGP\x01` |
| Flags | 1 byte | Control, FEC, migration, close, multipath, encryption |
| Reserved | 2 bytes | Zero for now |
| SessionID | 16 bytes | Stable session identifier used for migration |
| StreamID | 2 bytes | Logical stream ID |
| PacketNumber | 8 bytes | Monotonic packet number |
| FECGroup | 4 bytes | FEC group ID |
| FECIndex | 1 byte | Shard index within the group |
| FECTotal | 1 byte | Total data plus parity shards |
| FECDataShards | 1 byte | Original data shard count |
| Reserved | 1 byte | Zero for now |
| PayloadLength | 2 bytes | Encrypted payload length |

### 2.3 Flags

| Bit | Name | Meaning |
| --- | --- | --- |
| 0 | `FlagControl` | Control-plane packet |
| 1 | `FlagFEC` | FEC-only shard; do not deliver as a game payload |
| 2 | `FlagMigrate` | Path migration marker |
| 3 | `FlagClose` | Orderly close |
| 4 | `FlagMultipath` | Multipath duplicate |
| 5-6 | Reserved | Must be zero |
| 7 | `FlagEncrypted` | Inner payload is encrypted |

---

## 3. Session Lifecycle

```text
Client                                      Server
  | ---- HELLO (session id, client key) ----> |
  | <--- HELLO_ACK (same id, server key) ---- |
  | ==== encrypted data packets ============> |
  | <==== encrypted relay packets =========== |
  | ---- CLOSE -----------------------------> |
```

The implemented handshake uses X25519 ephemeral keys. Both sides derive
directional traffic keys from the shared secret and SessionID.

---

## 4. FEC Groups

### 4.1 Send Path

1. Real data shards are sent immediately. They are not held while waiting for a
   group to fill.
2. Every data shard payload is prefixed with a 2-byte original payload length.
   Reed-Solomon padding is therefore stripped safely after recovery.
3. The sender keeps a copy of data shards until `FECDataShards` payloads are
   collected or `GroupTimeout` expires.
4. When the group fills, the sender emits parity shards.
5. When `GroupTimeout` expires before the group fills, the sender emits
   FEC-only synthetic data shards for missing data indexes plus parity shards.

FEC-only synthetic data shards carry `FlagFEC`, so the receiver can use them for
reconstruction without delivering empty synthetic datagrams to the game socket.

### 4.2 Receive Path

1. Shards are buffered by `(SessionID, FECGroup)`.
2. Real data shards are delivered immediately after stripping the length prefix.
3. FEC-only shards are retained but not delivered.
4. If any original data shard is missing and the group has at least
   `FECDataShards` shards, Core reconstructs and delivers only the missing real
   payloads.
5. Completed groups remain in a bounded receive window so late originals or
   multipath duplicates are suppressed.

### 4.3 Dynamic FEC Ratio

Core adjusts parity ratio based on observed receive-side FEC recovery ratio. The
current implementation applies that estimate to the session's next outbound
groups as a conservative symmetry assumption. Explicit peer loss feedback is a
future control-plane upgrade.

| Observed recovery ratio | ParityShards/DataShards |
| --- | --- |
| 0% to 3% | 1/4, kept as a probe/protection floor |
| 3% to 10% | 2/4 |
| >10% | 4/4, ARQ-free maximum protection |

---

## 5. Connection Migration

When packets arrive from a new source address:

1. Core first authenticates the packet with AEAD.
2. If the SessionID matches and the source address changed, the return path is
   migrated to the new source.
3. Packet numbers are still deduplicated, so old-path and new-path duplicates
   do not reach the game socket twice.

Current migration is authenticated and zero-downtime, but explicit
`FlagMigrate` confirmation packets are still planned.

---

## 6. Multipath

The receive path deduplicates authenticated packet numbers, and
`MultipathTransport` can now compose multiple `Transport` implementations. Each
write is attempted on every path, while reads are merged from whichever path
delivers first. The remaining integration work is system-interface discovery
and policy selection, for example choosing Wi-Fi plus cellular paths on mobile.
The current adapter relies on PacketNumber deduplication; explicit
`FlagMultipath` marking remains reserved for a future control-plane integration.

---

## 7. Crypto

| Aspect | Choice |
| --- | --- |
| Key exchange | X25519 |
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| Outer camouflage | DTLS-like application-data record |

---

## 8. Current Limitations

- No explicit peer loss feedback yet; dynamic FEC currently uses receive-side
  recovery ratio as a conservative local estimate.
- No explicit migration-confirmation control packet yet.
- Multipath interface discovery and policy selection are not wired yet; the
  transport adapter and receive-side deduplication are implemented.
- `FlagMultipath` is reserved; current fan-out does not rewrite encrypted inner
  headers to set it.
- TGP does not implement ARQ retransmission by design; it relies on pacing and
  FEC to avoid adding physical RTT latency.
