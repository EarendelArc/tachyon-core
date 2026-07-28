# Captured UDP Core Contract

[中文](captured-udp-api.zh-CN.md)

## Status

The in-process controller, policy transaction, flow lease, and resource budget
registry is implemented and tested in `internal/capturedudp`. The Windows
named-pipe transport, privileged helper, Windows service, WFP policy manager,
callout driver, and packet injection path are not implemented. This document
must not be used as evidence that Tachyon already provides application-aware
capture.

## Boundary and readiness

The contract accepts only UDP flows that a privileged platform component has
already attributed and authorized. Core does not inspect PIDs or executable
paths on this path.

The public API can create only an unverified transport attachment. Such an
attachment cannot authenticate a controller. A future named-pipe transport in
this package must verify its OS peer before creating a verified attachment.
`Health.Ready` is true only while all of these conditions hold:

- a transport is attached;
- its OS peer is verified;
- exactly one controller is connected; and
- a committed policy generation is active.

No current code path claims that an OS peer has been verified.

## Controller contract

After verified transport attachment, Core generates a cryptographically random
256-bit one-use token internally. Authentication consumes that token and binds
the only controller capability to the attachment. Controller or transport
disconnect revokes the capability and clears prepared policy, active policy,
and flow leases. Payloads already handed to a caller remain charged against the
global byte budget until that caller invokes `Release()`.

```text
AttachTransport(verified transport) -> one-use token
Authenticate(attachment_id, token) -> sole controller
PrepareGeneration(generation) -> transaction
CommitGeneration(transaction)
AbortGeneration(transaction)
DisableGeneration(generation)
OpenFlow(flow_id, generation, family, local, original_destination) -> lease nonce
AcceptDatagram(flow_id, generation, lease_nonce, sequence, payload)
ResolveReply(TGP tunnel datagram) -> flow_id, generation, lease_nonce, payload
CloseFlow(generation, flow_id, lease_nonce)
Health()
Stats()
```

Prepare does not disturb the active generation or its flows. Commit atomically
replaces the active generation and invalidates its leases. Abort leaves the
active generation unchanged.

## TGP tunnel identity

Captured UDP uses the `TGD\x02` tunnel payload. It carries this identity inside
the payload protected by the established TGP session's ChaCha20-Poly1305 AEAD:

```text
FlowID[16] | generation[8] | lease_nonce[16] |
local endpoint | original remote endpoint | UDP payload
```

The server returns the exact identity and includes it in the UDP relay-flow
key. Core resolves replies by the complete identity and both endpoints, never
by tuple alone. Reusing a Flow ID or tuple creates a fresh random lease nonce,
so a late reply from an old lease cannot be delivered to the new lease.

`TGD\x01` remains parseable only for the legacy TUN preview. The captured-UDP
registry never emits it and rejects a v1 reply because it has no lease identity.
Partially populated v2 identities are invalid.

## Resource and lifetime invariants

- Generations are non-zero and monotonically committed.
- Flow leases have an idle TTL. A background reaper and hot-path checks remove
  expired leases.
- Flow count, datagram size, flow TTL, estimated flow metadata, and total
  outstanding payload bytes have non-configurable hard ceilings.
- Payload copying occurs after releasing the global registry lock.
- Accepted payloads and deliveries reserve the byte budget until callers invoke
  `Release()`. A leaked reservation fails closed with `ErrBufferBudget` rather
  than allowing unbounded allocation.
- Helper datagram sequences are strictly increasing per lease.
- Input and output payloads are copied at the trust boundary.

## Windows x64 closed-alpha sequence

1. Implement a versioned, length-prefixed named-pipe transport around this
   contract. Enforce pipe ACLs and verify the client process token before
   producing the currently unavailable verified transport attachment.
2. Build an in-tree Windows service/helper that owns transport lifecycle,
   policy transactions, watchdog, bypass identity, and direct-network rollback.
3. Add WFP management using a dynamic BFE session and atomic transactions. Do
   not claim capture until the callout data path exists.
4. Implement and audit an in-tree WDK callout covering IPv4, IPv6, connected
   UDP, and unconnected `sendto`, including injection-state loop prevention and
   original-destination preservation. Production distribution requires
   Microsoft-compatible signing.
5. Pass two-process same-destination, stale-lease, crash rollback, 100-cycle,
   1,000-generation, load, and resource-exhaustion tests before Prism enables it.

No kernel driver binary or third-party capture artifact is vendored here.

## Current alpha limitation

Wintun selective routes and PID reverse lookup remain a legacy diagnostic path.
They are not connected to this registry and are not application-isolated WFP
capture.
