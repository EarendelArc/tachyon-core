# Windows WFP Dataplane Status

## Status: NOT READY / NO-GO

The WFP source is an unsigned development checkpoint. It must not be installed,
loaded, distributed as usable, or enabled by Prism. A successful Go test or WDK
compile does not establish kernel runtime safety.

Receive injection is not implemented. The canonical ABI therefore does not
declare `INJECT_RECEIVE`, the Go provider returns `ErrCaptureUnavailable` from
delivery injection, and provider health never reports `ready`. Without an
active policy, every classify path keeps `FWP_ACTION_PERMIT`.

## Ownership model

Packets move through `Captured`, `Dequeued`, `Completing`, and exactly one of
`Completed` or `Cancelled`. CAS chooses the sole completion owner. The pending
list owns the base reference, dequeue/completion paths hold explicit local
references, and the allocation is freed only when the count reaches zero.

The user-space linearization model races dequeue, verdict, timeout, flush, and
output-buffer-too-small paths. It proves one terminal transition, one final
free, and a zero reference count for the model. It is not a substitute for
Driver Verifier or a checked-kernel VM.

## Canonical ABI

`drivers/windows/wfp/include/tachyon_wfp_abi.h` is the only numeric ABI source.
`go generate ./internal/helper` regenerates `wfp_abi_generated.go`; CI rejects a
dirty result. The header also owns the fixed driver/helper build IDs, canonical
UTF-8 Helper Service SID, its SHA-256 value, capabilities, structures, and
IOCTL definitions. C11 `_Static_assert` validates packed sizes in C builds.

## Helper transaction

For a future provider that can truthfully report ready, Helper runs capture and
the authenticated Named Pipe concurrently. Activation is ordered as Core
`PrepareGeneration`, WFP `ActivatePolicy`, then Core `CommitGeneration`.
Disconnect, component failure, activation failure, or close invokes WFP and
Core disable operations, cancels both goroutines, and waits for shutdown.

## Remaining evidence

- Successful x64 and ARM64 builds in the independent WDK workflow.
- Clean PREfast and InfVerif results.
- Driver Verifier, checked-kernel, forced cancellation, unload, and low-memory VM tests.
- Real receive injection with checksum, endpoint, compartment, and anti-loop validation.
- Test signing, install, upgrade, rollback, and uninstall procedures.
- Sustained queue/backpressure and game-traffic performance evidence.

Until all items are complete, the release decision remains **NO-GO**.
