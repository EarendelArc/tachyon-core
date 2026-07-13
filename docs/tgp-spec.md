# Tachyon Game Protocol (TGP) - Wire Format Specification

[Chinese](tgp-spec.zh-CN.md)

**Version:** TGP/1.0

**Status:** Draft

**Target audience:** Tachyon Core implementers

**Implementation status:** Core currently implements X25519/HKDF traffic-key
derivation with optional PSK authentication, ChaCha20-Poly1305 packet sealing/opening, Reed-Solomon FEC codec
primitives, receive-side FEC recovery in the live session path, token-bucket
pacing, UDP session handshake, client/relay session plumbing, authenticated
handshake source-address demux for relay sessions, send-side systematic FEC
parity generation, low-traffic FEC timeout flush, conservative dynamic FEC
ratio adjustment, and a sliding receive-side packet deduplication window in
`internal/tgp`. Core also includes a `MultipathTransport` adapter that fans out
writes across multiple underlying transports and merges reads from any path.
Explicit peer loss feedback remains planned; authenticated relay path
rebind/migration is implemented as described below.

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

### 2.1 Handshake

TGP session setup is a two-message UDP handshake:

```text
Client -> Server: Hello(session_id, client_x25519_public, optional_auth_tag)
Server -> Client: HelloAck(session_id, server_x25519_public, optional_auth_tag)
```

Both messages are wrapped in the DTLS-like outer header with sequence number
`0`. The body is:

```text
+----------------+----------------+-------------------------------+
| Magic "TGH\1"  | Type           | SessionID (16 bytes)          |
+----------------+----------------+-------------------------------+
| X25519 public key (32 bytes)                                    |
+---------------------------------------------------------------+
| Optional HMAC-SHA256 auth tag (32 bytes)                       |
+---------------------------------------------------------------+
```

When `tgp.auth.psk` is configured, the auth tag is mandatory:

```text
HMAC-SHA256(psk, magic || type || session_id || sender_public || peer_public)
```

`peer_public` is all zeroes in `Hello` and the client public key in
`HelloAck`. A server without a PSK rejects handshakes that include an auth tag,
and a server with a PSK rejects handshakes without a valid tag.

In server mode, Core requires `tgp.auth.psk` by default. Operators must set
`tgp.auth.allow_unauthenticated=true` explicitly to run an unauthenticated relay
for local development or compatibility testing. Generated templates do not
include a reusable default PSK; installers generate a fresh random PSK and store
it in `server.json` with restrictive file permissions.

### 2.2 Outer Header

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

### 2.3 Inner Header

The inner header and payload are encrypted with ChaCha20-Poly1305. Traffic
keys are derived with:

```text
HKDF-SHA256(
  shared_secret,
  salt=session_id when no PSK is configured,
  salt=SHA256(session_id || psk) when tgp.auth.psk is configured,
  info="tachyon-tgp-v1 traffic keys"
)
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

### 2.4 Flags

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

### 4.4 Protocol Resource Limits

Receivers reject oversized input before Reed-Solomon allocation or retained
buffer growth. TGP permits at most 32 data shards, 16 parity shards, 48 total
shards, 64 active receive groups, 4096 compact completed-group tombstones, and
4 MiB of retained shard payload per session. A shard cannot exceed the payload
budget of the maximum TGP datagram. Completed groups release shard storage
immediately; partial groups and tombstones expire after 30 seconds.

---

## 5. Connection Migration

The relay initially binds a session to the UDP source address that completed
the authenticated handshake. An additional migration or multipath source must
complete this control exchange before encrypted data from it can enter the
session queue:

1. The client sends `PathRequest(SessionID, ClientNonce, Tag)` from each path.
2. The relay verifies `Tag` with a path key derived from that session's
   client-to-server traffic key, then sends a fresh `ServerNonce` back to the
   observed UDP source.
3. The client verifies the challenge and returns
   `PathResponse(SessionID, ClientNonce, ServerNonce, Tag)` through the same
   local transport that received it.
4. The relay verifies a stateless, source-bound cookie carried in
   `ServerNonce`. Consumed cookies enter a short-lived per-session replay set;
   source mappings owned by another session cannot be stolen.

The request tag alone never registers a source, so replaying a captured request
from another address only produces a challenge that cannot be answered without
the per-session key. Requests allocate no global pending state. Replayed
responses fail the bounded per-session consumed-cookie check. Unknown
non-control data remains fail-closed and is not broadcast for trial decryption.

On the client, a `PathChallenge` is accepted only from the configured relay
endpoint established by the current handshake. A valid challenge forwarded
from any other source is discarded without authorizing that source or consuming
data anti-replay state. Relay endpoint migration requires a new handshake.

Packet numbers use a bounded sliding anti-replay window. Duplicates and packets
older than the window are rejected before delivery. Authorized data from any
path can be delivered, but it never changes the active return path; only a fresh
challenge completion does. Non-active paths expire after 45 seconds and the
oldest inactive entry is safely replaced when the eight-path bound is reached.

---

## 6. Multipath

The receive path deduplicates authenticated packet numbers, and
`MultipathTransport` composes multiple `Transport` implementations. Each write
is attempted on every path, reads are merged from whichever path delivers
first, and each local path performs the authenticated registration exchange
above. Registration refreshes periodically so changed NAT mappings remain
fail-closed until reauthenticated. The remaining integration work is
system-interface discovery and policy selection, for example choosing Wi-Fi
plus cellular paths on mobile. Explicit `FlagMultipath` marking remains
reserved for a future control-plane integration.

### 6.1 Datagram Size and PMTU

`tgp.max_datagram_size` caps the complete encrypted TGP UDP payload. The
default is 1352 bytes and the protocol maximum is 1452. With the default 1280
TUN MTU, the audited worst-case outer IPv6/UDP packet is 1396 bytes. The
minimum configurable value is 1232, matching an outer IPv6/UDP budget on a
known 1280-byte path. Client validation requires
`client.tun.mtu + 68 <= tgp.max_datagram_size`; oversized sends and receives
fail closed. Sends return an explicit protocol error and receive drops increment
`OversizedDatagrams` telemetry. The authenticated `TGH\x02` handshake carries
the offered limit in its authenticated fields, and both peers store the lower
client/relay value. Version 1 peers are rejected because they cannot prove a
datagram budget.

TGP does not currently fragment protocol datagrams or discover PMTU. Operators
must configure a known lower budget and matching TUN MTU. A 1280-byte outer
path cannot carry a minimum-size 1280-byte inner IPv6 packet without protocol
fragmentation, so that combination remains unsupported and fails closed; the
1232 setting is usable only when the captured traffic's inner MTU can also be
reduced safely, such as a controlled IPv4-only path.

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
- Relay path migration/rebind is fail-closed until the authenticated rebind
  exchange succeeds for the observed source address.
- Multipath interface discovery and policy selection are not wired yet; the
  transport adapter and receive-side deduplication are implemented.
- `FlagMultipath` is reserved; current fan-out does not rewrite encrypted inner
  headers to set it.
- There is no protocol fragmentation or automatic PMTU discovery; configured
  datagram and TUN limits must match the real path.
- TGP does not implement ARQ retransmission by design; it relies on pacing and
  FEC to avoid adding physical RTT latency.
