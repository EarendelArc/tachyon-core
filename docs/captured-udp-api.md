# Captured UDP Core Contract

[中文](captured-udp-api.zh-CN.md)

## Status

The in-process lease registry is implemented and tested in
`internal/capturedudp`. The Windows named-pipe transport, privileged helper,
Windows service, WFP policy manager, callout driver, and packet injection path
are not implemented. This document must not be used as evidence that Tachyon
already provides application-aware capture.

## Boundary

The contract accepts only UDP flows that a privileged platform component has
already attributed and authorized. Core does not inspect PIDs or executable
paths on this path.

An authenticated session can perform these operations:

```text
ActivateGeneration(generation)
DisableGeneration(generation)
OpenFlow(flow_id, generation, family, local_endpoint, original_destination)
AcceptDatagram(flow_id, generation, sequence, payload) -> TGP tunnel datagram
ResolveReply(TGP tunnel datagram) -> flow_id, generation, payload
CloseFlow(generation, flow_id)
Health()
Stats()
```

## Security invariants

- The per-launch session token is exactly 256 bits and is compared in constant
  time. A future transport must also authenticate the peer Windows token.
- Policy generations are non-zero and strictly increasing. Repeating the
  current activation or disable operation is idempotent.
- Replacing or disabling a generation invalidates all existing flow leases.
- Every helper datagram must reference an active generation and known Flow ID.
- Datagram sequences are strictly increasing per flow; replayed and reordered
  helper messages are rejected.
- Active local/remote tuples are unique because the current TGP tunnel payload
  does not carry the local Flow ID on its return path.
- Payloads and flow counts are bounded. Input and output payloads are copied at
  the trust boundary.
- Closing the registry clears the token and all leases.

The token is a second factor for the local channel, not a replacement for a
named-pipe ACL, peer-process token validation, service SID, or signed binary
policy.

## Windows x64 closed-alpha sequence

1. Add a versioned, length-prefixed named-pipe protocol around this registry.
   Restrict the pipe to LocalSystem, the Tachyon service SID, and the active
   interactive user selected by the orchestrator. Verify the client process
   token before accepting the random session token.
2. Build an in-tree Windows service/helper that owns the pipe connection,
   policy transaction, health watchdog, bypass identity, and direct-network
   rollback. At this stage it is a contract harness, not packet capture.
3. Build WFP management with a dynamic BFE session and atomic transactions.
   This can validate application/user/UDP policy selection, but must not claim
   redirection until a real callout data path exists.
4. Implement and audit an in-tree WDK callout driver covering IPv4, IPv6,
   connected UDP, and unconnected `sendto`, including injection-state loop
   prevention and original-destination preservation. Production distribution
   requires appropriate Microsoft-compatible signing.
5. Run the two-process same-destination test, crash rollback, 100-cycle and
   1,000-generation replacement tests before enabling the feature in Prism.

No kernel driver binary or third-party capture artifact is vendored by this
contract step.

## Current alpha limitation

Wintun selective routes and PID reverse lookup remain a legacy diagnostic path.
They are not connected to this registry and are not application-isolated WFP
capture.
