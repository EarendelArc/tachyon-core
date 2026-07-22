# ADR-0001: Application-Aware Capture

[中文](0001-application-aware-capture.zh-CN.md)

- Status: Proposed
- Date: 2026-07-22
- Scope: Tachyon Core, Tachyon Prism, and privileged platform integration

## Context

Tachyon must accelerate UDP traffic from selected game applications without
capturing unrelated traffic from another process that contacts the same remote
address. Game servers may use dynamic addresses, CDN or relay pools, and
short-lived endpoints, so destination CIDRs cannot be the primary application
selector.

The current client preview installs explicit destination routes into a TUN and
looks up the owning process after a packet has entered Core. This path cannot
safely return a non-game packet to the native network path without creating a
route loop. Process lookup is also too expensive and uncertain to remain in the
latency-sensitive packet path. The current selective-route TUN implementation
is therefore a legacy preview, not the target application-aware architecture.

Core must remain a pure TGP data plane. Prism remains the dual-core GUI and
orchestrator for Xray Core and Tachyon Core. Operating-system capture and
privileged policy enforcement need a separate boundary.

## Decision Drivers

1. A selected process must be distinguishable from an unselected process even
   when both use the same protocol, destination, and port.
2. Dynamic game endpoints must work without maintaining broad destination
   CIDRs.
3. Unselected and unidentified traffic must stay on the native path.
4. Core, helper, Xray, and Relay traffic must never re-enter the capture path.
5. Capture activation, replacement, and removal must be transactional and
   fail open to direct networking for this consumer game-acceleration product.
6. The UI must remain unprivileged, and platform-specific kernel or system APIs
   must not be implemented in the Tauri view layer.

## Decision

Process classification happens in the platform capture layer before traffic is
accepted by Tachyon Core. Core receives only UDP flows that the platform layer
has already authorized for game acceleration.

```text
Prism UI
  -> Prism Rust orchestrator
  -> privileged platform capture helper or extension
  -> authenticated local captured-UDP API
  -> Tachyon Core / TGP
  -> Tachyon Server
```

Wintun and utun may be platform packet transports, but they are not process
classifiers. A global TUN followed by PID reverse lookup is not an acceptable
production implementation of this decision.

## Ownership Boundaries

| Component | Owns | Must not own |
| --- | --- | --- |
| Prism UI | Program selection, Steam UX, settings, permission guidance, status, and recovery UX | Driver installation logic, elevation commands, route mutation, packet processing |
| Prism Rust backend | Configuration orchestration, process lifecycle, policy transactions, helper RPC, readiness, and aggregated status | TGP crypto/FEC or direct kernel-filter implementation |
| Platform helper or extension | Process identity, OS capture, original-destination preservation, bypass, native reinjection, and rollback | Subscriptions, Xray JSON, or TGP transport |
| Tachyon Core | Captured flow to TGP-session mapping, encryption, FEC, pacing, multipath, Relay transport, and telemetry | PID lookup, launcher scanning, WFP, Network Extension, nftables, Xray, or subscriptions |
| Tachyon Server | TGP authentication, recovery, deduplication, ACLs, and UDP relay | Client application policy |
| Xray Core | Ordinary proxy traffic described by Prism-generated Xray JSON | Tachyon game UDP |

Driver, helper, and extension logic belongs in separately testable platform
targets. It must not be embedded in React components or ordinary Tauri command
handlers.

## Cross-Platform Capture Contract

The privileged platform adapter exposes a common control contract to the Prism
Rust backend:

```text
Capabilities() -> platform features and limitations
PreparePolicy(policy, generation) -> transaction handle
CommitPolicy(transaction) -> active generation
RollbackPolicy(transaction or generation)
AttachProcess(process_identity, policy_id)
DetachProcess(process_identity, policy_id)
DisableCapture(generation)
Health() -> readiness, active generation, stale-state report
Statistics() -> captured, bypassed, rejected, and recovered flows
```

The Core-facing local data plane is process-agnostic:

```text
OpenFlow(flow_id, original_destination, address_family, policy_generation)
SendDatagram(flow_id, sequence, payload)
ReceiveDatagram(flow_id, payload)
CloseFlow(flow_id, reason)
Health()
Statistics()
```

Windows uses a named pipe; macOS and Linux use Unix domain sockets. The local
channel authenticates the OS identity of its peer and a per-launch random
session token. Core rejects unknown generations and flow IDs.

## Windows Decision

The production Windows path uses Windows Filtering Platform application-layer
enforcement and a signed callout/helper combination. Filters match the original
application identity, user identity, UDP, and IPv4 or IPv6 before redirecting
or absorbing the selected flow. The helper preserves the original destination
and exchanges datagrams with Core.

The implementation must cover connected UDP and unconnected `sendto` traffic.
ALE connect redirection alone is insufficient unless tests prove coverage for
both forms; datagram-layer classification and injection may also be required.
Redirect records, original application identity, and original destination are
carried through outbound proxy sockets as required by WFP.

WFP policy objects use a dynamic WFP session and an atomic WFP transaction.
Dynamic filters disappear when the owning helper session closes or crashes.
Core, the helper, Xray, Relay endpoints, loopback, and required system traffic
receive higher-priority bypass rules.

Wintun remains available only as a legacy preview and diagnostic transport. It
must not be presented as process-isolated capture.

## macOS Decision

The preferred consumer path is a Developer ID-signed Network Extension system
extension based on `NETransparentProxyProvider`. It includes eligible outbound
UDP flows and delegates selected flows to Core. A flow that cannot be reliably
identified or is not selected proceeds directly through the transparent
provider's native bypass behavior.

MDM Per-App VPN is not the consumer product foundation because its app rules
are associated with managed application deployment. Before implementation is
committed, a feasibility spike must prove that an unmanaged desktop build can
obtain stable source process identity, including signing identifier or audit
token, for the required UDP flows. If that proof fails, macOS remains a
destination-rule preview and must not claim arbitrary per-process capture.

utun remains a packet transport for compatibility experiments. It is not the
process-policy authority.

## Linux Decision

The production Linux path uses cgroup v2 as the runtime application identity.
The privileged helper launches or moves selected game processes into a
dedicated Tachyon game cgroup. Descendants inherit that cgroup. nftables socket
cgroup matching marks only public UDP from that cgroup, and an `ip rule` plus a
dedicated routing table directs marked packets to the capture interface.

Core, Prism, the helper, and Xray run in a bypass cgroup. Relay destinations,
loopback, local networks, DNS, DHCP, and other required control traffic are
excluded before marking. nftables, policy rules, routes, and the capture
interface are created and replaced atomically where the platform permits.

"Launch with Tachyon" is the reliable Linux MVP. Attaching an already-running
process is best effort until tests prove that moving the process and following
its children cannot miss the relevant first flow. Steam integration should use
a controlled launcher or wrapper rather than broad destination routes.

## Application Policy

The Prism-owned policy model contains at least:

```text
policy_id
generation
platform_identity
protocol = UDP
include_ports / exclude_ports
exclude_loopback / exclude_lan / exclude_dns
relay_endpoints
fail_mode = direct
```

Platform identities are:

- Windows: canonical executable path, publisher identity, package SID when
  applicable, and an optional file hash. A hash is not the sole identity
  because game updates replace binaries.
- macOS: Team ID, signing identifier, designated requirement, and audit token.
  A path is display metadata or a documented fallback, not the primary signed
  identity.
- Linux: the runtime cgroup ID is authoritative. Executable path, inode, UID,
  and launcher metadata are used to create or attach the process.

The default selected-application scope is all public UDP, with explicit
exclusions. Optional port and CIDR rules narrow the scope but are not required
to discover dynamic game servers. TCP continues through the native path or the
separately configured Xray path.

## Direct Path and Loop Prevention

Unselected applications never enter the capture data path. Unknown identities
and unsupported flows stay direct. Direct fallback is implemented by the
platform capture layer, not by writing packets from Core back into the same
TUN.

Every captured flow has a generation-bound flow lease containing the original
destination and platform policy identity. A helper must not open a Core flow
without that lease. Core traffic is exempt by OS identity and helper-specific
bypass state; destination exclusions are defense in depth, not the only loop
protection.

For Linux, selection has already occurred through cgroup membership. A packet
from any other cgroup must not be marked. If the helper or Core becomes
unhealthy, capture policy is removed so subsequent datagrams use the native
route. In-flight NAT state may be lost; fail-open means avoiding a black hole,
not promising uninterrupted sessions after a local component failure.

## Lifecycle, Failure, and Rollback

Startup order is fixed:

```text
validate configuration
start Core and wait for data-plane readiness
start helper or extension and verify bypasses
prepare platform policy generation N
commit generation N atomically
report acceleration active
```

Shutdown order is fixed:

```text
disable generation N atomically
wait for or expire flow leases
remove routes, filters, and temporary OS state
stop Core and helper
report direct networking restored
```

Policy replacement prepares generation N+1 before switching from N. A failed
prepare or commit leaves N active. A failed initial activation leaves capture
disabled. Prism persists only the desired policy, while the helper journals the
minimum identifiers needed to detect and remove stale privileged state.

Consumer game acceleration defaults to fail-open direct networking. Windows
uses dynamic WFP objects. macOS returns or transitions unhandled flows to the
native path as supported by Network Extension. Linux uses a supervised helper
with mandatory stop-post cleanup and an independent watchdog capable of
removing Tachyon's dedicated nftables table, rules, and routes after a crash.

## Privilege, Signing, and Distribution

- The Prism UI runs without elevation on every platform.
- Windows uses a service with a restricted control ACL. Production kernel
  components require Microsoft-compatible release signing; test-signed drivers
  are not production artifacts.
- macOS requires Developer ID signing, notarization, Network Extension
  entitlements, system-extension packaging, and explicit user approval. App
  Store and outside-store capability profiles are validated separately.
- Linux grants only the capabilities required by the helper, normally
  `CAP_NET_ADMIN` and, when the selected implementation needs it, `CAP_BPF`.
  The GUI is never run as root.
- Local control APIs reject unprivileged users other than the interactive user
  who owns the Prism session and the installed service identity.

## Minimum Delivery Sequence

1. Specify and test the captured-UDP API, policy generations, helper health,
   and transaction semantics. Remove PID lookup from Core's production packet
   path while retaining the legacy preview behind an explicit mode.
2. Deliver Windows x64 and ARM64 WFP capture as the first supported MVP. Keep
   Wintun destination routes visibly labeled legacy preview.
3. Deliver Linux cgroup launch mode, nftables marking, policy routing, bypass,
   and crash cleanup. Add attach-to-running-process only after race testing.
4. Complete the macOS Network Extension identity and distribution spike. Plan
   implementation only if the P0 identity and bypass criteria are proven.
5. Add Steam automation, running-process attachment, policy migration,
   multipath interface integration, and field telemetry after the platform
   foundations pass P0.

## P0 Acceptance Criteria

1. For two processes using the same destination and port concurrently, only
   the selected process enters TGP; the other remains direct.
2. IPv4, IPv6, connected UDP, and unconnected UDP pass the platform suite.
3. A selected process can contact rapidly changing public destinations without
   updating CIDRs.
4. Game TCP, system DNS, loopback, LAN, Core, Prism, helper, Xray, and Relay
   transport do not enter TGP.
5. Killing Prism, Core, or the helper restores direct networking within one
   second and leaves no stale WFP filters, nftables objects, policy rules,
   routes, adapters, or active policy generation.
6. One hundred start/stop cycles and one thousand policy replacements leave no
   duplicate filters, stale generations, leaked handles, or route state.
7. At 5,000 UDP datagrams per second for 30 minutes, the host capture layer
   loses no packet, adds no more than 1 ms P99 local latency, and reports all
   drops and bypass decisions.
8. Steam child processes, binary updates, ordinary and administrator sessions,
   sleep/resume, interface changes, and helper upgrades have automated tests.
9. Installation, upgrade, rollback, and uninstall restore the exact prior OS
   networking state, including recovery from process termination during every
   transaction phase.
10. macOS cannot pass the per-process milestone until stable source identity is
    demonstrated in a signed, notarized, unmanaged desktop build.

## Consequences

This design removes PID reverse lookup and broad destination ownership from the
normal Core packet path. Dynamic game endpoints become a natural consequence
of process selection, and non-game traffic remains safe because it is never
captured.

The cost is a substantial platform-integration and signing program. Windows
requires a production-quality WFP component, macOS depends on Network Extension
capability and distribution validation, and Linux needs carefully supervised
privileged networking state. Cross-platform parity is defined by the common
contract and acceptance tests, not by forcing every OS to use TUN.

## Rejected Alternatives

### Destination CIDRs plus TUN

Rejected as the target architecture. It cannot distinguish processes sharing a
destination, requires ongoing endpoint discovery, and cannot safely return an
incorrectly captured packet through the same route. It remains legacy preview.

### Global TUN plus PID reverse lookup in Core

Rejected. Attribution is late, potentially ambiguous, expensive on misses, and
leaves Core responsible for native forwarding and loop prevention.

### Platform drivers inside Tachyon Core

Rejected. It would mix privileged OS policy with TGP transport, complicate
mobile portability, and make Core releases depend on platform signing.

### Platform logic inside Prism UI components

Rejected. UI reloads, renderer failures, and frontend updates must not own
privileged network state.

## References

- [Microsoft: Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)
- [Microsoft: Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [Microsoft: WFP Dynamic Sessions](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)
- [Apple: NETransparentProxyProvider](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
- [Apple: Network Extension Provider Deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Apple: Network Extensions Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [nftables: socket cgroupv2 expression](https://netfilter.org/projects/nftables/manpage.html)
- [Linux kernel: BPF program types and cgroup hooks](https://docs.kernel.org/bpf/libbpf/program_types.html)
