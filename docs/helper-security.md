# Windows Helper Security Boundary

## Scope

tachyon-core helper --console and tachyon-core helper --service are two launch
modes for the same binary. The helper is the client of Captured UDP Named Pipe
v2; Core remains the authenticated protocol endpoint. The helper performs
Hello/token authentication, Ping/Pong, generation transactions, flow leases,
datagrams, and delivery mapping. A broken pipe is closed, pending buffers are
bounded, reconnects use exponential backoff, and session tokens and frame
buffers are zeroized.

The default CaptureProvider is an explicit fail-closed provider:
status=not_ready, no capabilities, and no packet callbacks. Therefore the
helper never reports capture-ready and never fabricates traffic.

## Service policy

scripts/install-helper-service.ps1 installs the same binary as LocalService,
configures RpcSs as a dependency, sets a restricted Service SID, limits service
administration, and installs restart recovery. The Core Named Pipe ACL must
contain only the intended restricted helper/service SID. allow_insecure_user_sid
is not used by the service installation.

Usage:

~~~powershell
.\scripts\install-helper-service.ps1 -BinaryPath .\tachyon-core.exe
.\scripts\diagnose-helper-service.ps1
.\scripts\test-helper-security.ps1 -RunServiceSIDHarness
.\scripts\test-helper-security.ps1 -RunGoHarness
.\scripts\uninstall-helper-service.ps1
~~~

The temporary Service SID harness requires an elevated PowerShell session. It
builds no driver and starts only a test-only Core Named Pipe endpoint from the
same binary, then verifies Service SID ACL admission, server image/hash
identity, token authentication, reconnect-safe health reporting, and the
required NotReady state. Cleanup stops and deletes the unique temporary SCM
service even on failure. The Go harness covers wrong-SID ACL denial,
low-integrity rejection, and enabled service-group matching. A CI or release
machine must treat a missing administrator harness as a gate failure when
privileged testing is required.

## Threat model

The helper is treated as a privileged boundary and Core as an untrusted peer
until the operating-system pipe identity and ACL have been verified. The
protocol rejects stale tokens, replayed request IDs, invalid flow identity,
stale generation, oversized frames, and resource exhaustion. Delivery is
accepted only through the authenticated Core session and is passed to an
Injector contract; the default injector rejects it.

This release does not contain a WFP callout provider, signed driver, WFP
capture, process capture, kernel injection, or a game-acceleration
implementation. The WFP contract in internal/helper is a versioned interface
document only. Health must remain not_ready until a separately reviewed and
signed provider implements that contract.
