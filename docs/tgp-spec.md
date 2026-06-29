# Tachyon Game Protocol (TGP) — Wire Format Specification

[中文说明](tgp-spec.zh-CN.md)

**Version:** TGP/1.0

**Status:** Draft

**Target audience:** Core and Server implementers

**Implementation status:** Core currently implements X25519/HKDF traffic-key
derivation, ChaCha20-Poly1305 packet sealing/opening, Reed-Solomon FEC codec
primitives, token-bucket pacing, UDP session handshake, client/relay session
plumbing, authenticated source-address migration, and a sliding receive-side
packet deduplication window in `internal/tgp`. Migration confirmation control
packets, dynamic FEC grouping inside the live session path, and true multi-
transport fan-out are planned next.

---

## 1. Goals

TGP is a purpose-built UDP transport protocol designed to replace QUIC-based
game proxies (TUIC, Hysteria 2) for latency-sensitive game traffic.

| Goal | Mechanism |
|---|---|
| Zero jitter | Token-Bucket Pacing (no burst) |
| 0-RTT loss recovery | Reed-Solomon FEC (20%–50% parity) |
| Connection migration | 128-bit Session ID |
| DPI resistance | DTLS 1.0 outer header + ChaCha20-Poly1305 |
| Multipath | Fan-out write + sliding-window dedup |

---

## 2. Packet Structure

All integers are **big-endian** on the wire.

### 2.1 Outer Header (13 bytes, plaintext)

Mimics a DTLS 1.0 Record header (`RFC 6347 §4.1`):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────┬─────────────────┬─────────────────────────────┤
│ ContentType (1) │ Version (2)     │ Epoch (2)                   │
├─────────────────────────────────────────────────────────────────┤
│ SequenceNumber (6 bytes)                                        │
├─────────────────────────────────────────────────────────────────┤
│ Length (2)                                                      │
└─────────────────────────────────────────────────────────────────┘
```

| Field | Size | Value |
|---|---|---|
| ContentType | 1 byte | `0x17` (application_data) |
| Version | 2 bytes | `0xFE 0xFF` (DTLS 1.0) |
| Epoch | 2 bytes | `0x0000` initially; randomised per session |
| SequenceNumber | 6 bytes | Random per packet for DPI evasion |
| Length | 2 bytes | Byte length of the encrypted inner payload |

### 2.2 Inner Header (43 bytes, authenticated encrypted)

The inner header and payload are encrypted with **ChaCha20-Poly1305** (IETF).
Key derivation: `HKDF-SHA256(shared_secret, salt=session_id,
info="tachyon-tgp-v1 traffic keys")`.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│ Magic (4 bytes): 0x54 0x47 0x50 0x01  "TGP\x01"                │
├─────────────────┬─────────────────────────────────────────────-─┤
│ Flags (1)       │ Reserved (2 bytes)                            │
├─────────────────────────────────────────────────────────────────┤
│ SessionID (16 bytes — UUIDv4)                                   │
│                                                                 │
│                                                                 │
│                                                                 │
├─────────────────┬───────────────────────────────────────────────┤
│ StreamID (2)    │                                               │
├─────────────────┘                                               │
│ PacketNumber (8 bytes — monotonic per stream)                   │
│                                                                 │
├─────────────────┬───────────────┬───────────────┬──────────────┤
│ FECGroup (4)    │ FECIdx (1)    │ FECTotal (1)  │ FECData (1)  │
├─────────────────┴───────────────┴───────────────┴──────────────┤
│ Reserved (1)    │ PayloadLength (2)                             │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Flags Byte

| Bit | Name | Meaning |
|---|---|---|
| 0 | `FlagControl` | Control plane packet (handshake, keepalive) |
| 1 | `FlagFEC` | This is a parity shard (not original data) |
| 2 | `FlagMigrate` | Client is requesting path migration |
| 3 | `FlagClose` | Orderly session teardown |
| 4 | `FlagMultipath` | Duplicate sent on a second path; dedup required |
| 5–6 | Reserved | Must be 0 |
| 7 | `FlagEncrypted` | Inner payload is ChaCha20 encrypted (always 1) |

---

## 3. Session Lifecycle

```
Client                                    Server
  │                                          │
  │──── HELLO (FlagControl, CID=random) ────►│
  │                                          │
  │◄─── HELLO_ACK (FlagControl, same CID) ──│
  │                                          │
  │════ Data packets (FlagEncrypted) ═══════►│
  │◄═══════════════════════════════ Relay ═══│
  │                                          │
  │──── CLOSE (FlagClose) ──────────────────►│
  │◄─── CLOSE_ACK ──────────────────────────│
```

### 3.1 HELLO Packet Control Body (after inner header)

```json
{
  "version": 1,
  "client_pubkey": "<X25519 ephemeral public key, base64>",
  "timestamp": 1700000000
}
```

### 3.2 HELLO_ACK Packet Control Body

```json
{
  "server_pubkey": "<X25519 ephemeral public key, base64>",
  "session_id": "<UUID assigned by server>",
  "max_streams": 16
}
```

---

## 4. FEC Groups

### 4.1 Encoding (Client)

1. Accumulate `FECDataShards` (e.g. 4) game UDP payloads.
2. Zero-pad all payloads to the length of the longest one.
3. Call `RS.Encode(data, dataShards, parityShards)` → produces parity shards.
4. Send all data + parity shards with the same `FECGroup` number.
5. Each shard has `FECIndex` 0…(FECTotal-1) and `FECDataShards` set.

### 4.2 Reconstruction (Server)

1. Buffer shards by `(SessionID, FECGroup)`.
2. If all `FECDataShards` data shards arrive → deliver immediately, skip RS.
3. If any shard is missing but `received_count >= FECDataShards` → reconstruct.
4. If group timeout (20 ms) expires and `received_count < FECDataShards` → deliver partial.

### 4.3 Dynamic FEC Rate Adjustment

The client adjusts parity ratio based on measured loss rate, computed over a
30-second sliding window:

| Loss Rate | ParityShards/DataShards |
|---|---|
| 0% | 0/N (FEC disabled) |
| 1–3% | 1/4 (25%) |
| 3–10% | 2/4 (50%) |
| >10% | 4/4 (100%, fallback to ARQ-free max protection) |

---

## 5. Connection Migration

When the client detects a local IP change (e.g., Wi-Fi → 5G):

1. Client starts sending packets from the new address with `FlagMigrate=1`.
2. Server sees packets from a new source addr with a known `SessionID`.
3. Server validates the packet (AEAD decrypt succeeds → proves ownership of session key).
4. Server updates its routing table: `SessionID → newAddr`.
5. Current implementation immediately updates the session return path after
   authenticated decrypt succeeds. A future control packet with `FlagMigrate=1`
   will make the confirmation explicit.
6. Client drops the old path after it observes traffic on the new path.

**Migration is zero-downtime**: during the migration window (≤100 ms), packets
from both old and new paths are accepted (dedup buffer prevents doubles).

---

## 6. Multipath

When the client has both Wi-Fi and cellular available:

1. Both `Transport` instances are registered with `MultipathTransport`.
2. `MultipathTransport.WritePacket()` fans out to all paths simultaneously with `FlagMultipath=1`.
3. The receiver tracks authenticated `PacketNumber` values in a sliding window.
   Duplicates are silently dropped before delivery to the game socket.

Current Core exposes the receive-side dedup window in `DatagramSession`.
`MultipathTransport` fan-out is still an integration target.

---

## 7. Crypto

| Aspect | Choice | Rationale |
|---|---|---|
| Key Exchange | X25519 ECDH | Fast, no patent issues, used by TLS 1.3 |
| KDF | HKDF-SHA256 | RFC 5869, standard |
| AEAD | ChaCha20-Poly1305 (IETF, RFC 8439) | Faster than AES-GCM without hardware acceleration (mobile) |
| Nonce | Derived from PacketNumber + SessionID | Eliminates nonce reuse risk |

---

## 8. Obfuscation Details

The goal is to make TGP traffic indistinguishable from real DTLS 1.0 traffic
to passive DPI. Active probing resistance is a future goal.

- `ContentType = 0x17`: All production TGP packets use application_data type.
  DTLS handshake types (0x16) are never used to avoid confusing real DTLS stacks.
- `Version = 0xFEFF`: DTLS 1.0 is the most common version seen in WebRTC ICE traffic.
- `SequenceNumber`: Randomised per packet. Real DTLS sequences are monotonic,
  but ISPs cannot distinguish random-looking sequences without deep state tracking.
- `Epoch`: Incremented on migration (mirrors real DTLS re-key behaviour).

---

## 9. Implementation Notes

- The 16-byte Poly1305 authentication tag is appended after the inner payload.
  Total per-packet overhead = 16 (outer) + 36 (inner) + 16 (Poly1305) = **68 bytes**.
- For typical game packets of 64 bytes, this is a 106% overhead.
  For 256-byte packets, overhead is 26%. FEC adds further overhead per config.
- Implementations MUST reject packets where `Magic != [0x54,0x47,0x50,0x01]`
  after decryption (prevents oracle attacks).
