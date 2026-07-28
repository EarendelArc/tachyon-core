package capturedudp

import (
	"errors"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestUnverifiedTransportCannotAuthenticateOrBecomeReady(t *testing.T) {
	registry := testRegistry(t, Limits{})
	attachment, err := registry.NewUnverifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AttachTransport(attachment); !errors.Is(err, ErrTransportNotVerified) {
		t.Fatalf("attach unverified transport error = %v", err)
	}
	health := registry.Health()
	if health.Ready || health.TransportAttached || health.TransportPeerVerified || health.ControllerConnected {
		t.Fatalf("unverified transport health = %+v", health)
	}
	if _, err := registry.Authenticate(attachment, SessionToken{}); !errors.Is(err, ErrTransportMismatch) {
		t.Fatalf("authenticate unverified transport error = %v", err)
	}
}

func TestControllerIsSingleUseBoundAndDisconnectRevokesState(t *testing.T) {
	registry := testRegistry(t, Limits{})
	attachment, err := registry.newVerifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	token, err := registry.AttachTransport(attachment)
	if err != nil {
		t.Fatal(err)
	}
	other, err := registry.newVerifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Authenticate(other, token); !errors.Is(err, ErrTransportMismatch) {
		t.Fatalf("cross-transport authentication error = %v", err)
	}
	controller, err := registry.Authenticate(attachment, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Authenticate(attachment, token); !errors.Is(err, ErrControllerActive) {
		t.Fatalf("second controller error = %v", err)
	}
	commitGeneration(t, controller, 1)
	lease, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	if !registry.Health().Ready {
		t.Fatal("verified controller with active generation was not ready")
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	health := registry.Health()
	if health.Ready || health.TransportAttached || health.ControllerConnected || health.ActiveGeneration != 0 || health.OpenFlows != 0 {
		t.Fatalf("health after controller disconnect = %+v", health)
	}
	if _, err := controller.AcceptDatagram(testDatagram(lease, 0, "late")); !errors.Is(err, ErrControllerRevoked) {
		t.Fatalf("revoked controller error = %v", err)
	}
}

func TestAttachReplacementAndForeignDetachHaveNoSideEffects(t *testing.T) {
	registry, controller := testController(t, Limits{})
	commitGeneration(t, controller, 1)
	lease, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := registry.newVerifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AttachTransport(replacement); !errors.Is(err, ErrTransportActive) {
		t.Fatalf("replacement attach error = %v", err)
	}
	unverified, err := registry.NewUnverifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AttachTransport(unverified); !errors.Is(err, ErrTransportNotVerified) {
		t.Fatalf("unverified replacement error = %v", err)
	}
	if err := replacement.Detach(); !errors.Is(err, ErrTransportMismatch) {
		t.Fatalf("foreign detach error = %v", err)
	}
	accepted, err := controller.AcceptDatagram(testDatagram(lease, 0, "active"))
	if err != nil {
		t.Fatalf("failed attach attempt revoked active controller: %v", err)
	}
	accepted.Release()
	if !registry.Health().Ready {
		t.Fatal("failed attach attempt changed active health")
	}
}

func TestGenerationPrepareAbortAndCommitAreTransactional(t *testing.T) {
	registry, controller := testController(t, Limits{})
	commitGeneration(t, controller, 10)
	lease, err := controller.OpenFlow(testFlow(1, 10, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := controller.PrepareGeneration(11)
	if err != nil {
		t.Fatal(err)
	}
	health := registry.Health()
	if health.ActiveGeneration != 10 || health.PreparedGeneration != 11 || health.OpenFlows != 1 {
		t.Fatalf("health while prepared = %+v", health)
	}
	if err := controller.AbortGeneration(transaction); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.AcceptDatagram(testDatagram(lease, 0, "still-active")); err != nil {
		t.Fatalf("aborted replacement disturbed active generation: %v", err)
	}
	transaction, err = controller.PrepareGeneration(11)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.CommitGeneration(transaction); err != nil {
		t.Fatal(err)
	}
	health = registry.Health()
	if health.ActiveGeneration != 11 || health.PreparedGeneration != 0 || health.OpenFlows != 0 {
		t.Fatalf("health after commit = %+v", health)
	}
	if _, err := controller.PrepareGeneration(10); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale prepare error = %v", err)
	}
}

func TestLeaseIdentityPreventsLateReplyDeliveryAfterReuse(t *testing.T) {
	_, controller := testController(t, Limits{})
	commitGeneration(t, controller, 1)
	spec := testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015")
	oldLease, err := controller.OpenFlow(spec)
	if err != nil {
		t.Fatal(err)
	}
	oldPacket, err := controller.AcceptDatagram(testDatagram(oldLease, 0, "old"))
	if err != nil {
		t.Fatal(err)
	}
	oldWire := oldPacket.Datagram
	oldPacket.Release()

	commitGeneration(t, controller, 2)
	spec.Generation = 2
	newLease, err := controller.OpenFlow(spec)
	if err != nil {
		t.Fatal(err)
	}
	if oldLease.LeaseNonce == newLease.LeaseNonce {
		t.Fatal("reused flow received the same lease nonce")
	}
	oldWire.Payload = []byte("late-old-reply")
	if _, err := controller.ResolveReply(oldWire); !errors.Is(err, ErrUnknownFlow) {
		t.Fatalf("late old lease reply error = %v", err)
	}

	newPacket, err := controller.AcceptDatagram(testDatagram(newLease, 0, "new"))
	if err != nil {
		t.Fatal(err)
	}
	reply := newPacket.Datagram
	newPacket.Release()
	reply.Payload = []byte("new-reply")
	delivery, err := controller.ResolveReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	defer delivery.Release()
	if delivery.FlowID != newLease.FlowID || delivery.Generation != 2 || delivery.LeaseNonce != newLease.LeaseNonce || string(delivery.Payload) != "new-reply" {
		t.Fatalf("new lease delivery = %+v", delivery)
	}
}

func TestCapturedReplyRejectsLegacyTunnelV1(t *testing.T) {
	_, controller := testController(t, Limits{})
	commitGeneration(t, controller, 1)
	if _, err := controller.ResolveReply(tgp.TunnelDatagram{
		LocalIP: netip.MustParseAddr("10.0.0.2"), LocalPort: 40000,
		RemoteIP: netip.MustParseAddr("203.0.113.9"), RemotePort: 27015,
	}); !errors.Is(err, ErrMissingLeaseIdentity) {
		t.Fatalf("legacy reply error = %v", err)
	}
}

func TestFlowTTLExpiresInactiveLease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry, err := newRegistry(registryOptions{
		limits:       Limits{FlowTTL: time.Second},
		now:          func() time.Time { return now },
		reapInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	controller := attachController(t, registry)
	commitGeneration(t, controller, 1)
	lease, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	registry.expireFlowsAt(now)
	if registry.Health().OpenFlows != 0 || registry.Stats().FlowsExpired != 1 {
		t.Fatalf("expired flow state: health=%+v stats=%+v", registry.Health(), registry.Stats())
	}
	if _, err := controller.AcceptDatagram(testDatagram(lease, 0, "late")); !errors.Is(err, ErrUnknownFlow) {
		t.Fatalf("expired flow datagram error = %v", err)
	}
}

func TestBufferedByteBudgetRequiresRelease(t *testing.T) {
	registry, controller := testController(t, Limits{MaxDatagramSize: 4, MaxBufferedBytes: 4})
	commitGeneration(t, controller, 1)
	first, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.OpenFlow(testFlow(2, 1, "10.0.0.2:40001", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := controller.AcceptDatagram(testDatagram(first, 0, "four"))
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.Health().BufferedBytes; got != 4 {
		t.Fatalf("buffered bytes = %d, want 4", got)
	}
	if _, err := controller.AcceptDatagram(testDatagram(second, 0, "x")); !errors.Is(err, ErrBufferBudget) {
		t.Fatalf("buffer budget error = %v", err)
	}
	accepted.Release()
	if got := registry.Health().BufferedBytes; got != 0 {
		t.Fatalf("buffered bytes after release = %d", got)
	}
	accepted, err = controller.AcceptDatagram(testDatagram(second, 1, "x"))
	if err != nil {
		t.Fatal(err)
	}
	accepted.Release()
}

func TestBufferedByteBudgetCannotBeResetByGenerationReplacement(t *testing.T) {
	registry, controller := testController(t, Limits{MaxDatagramSize: 4, MaxBufferedBytes: 4})
	commitGeneration(t, controller, 1)
	oldLease, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := controller.AcceptDatagram(testDatagram(oldLease, 0, "four"))
	if err != nil {
		t.Fatal(err)
	}
	commitGeneration(t, controller, 2)
	if got := registry.Health().BufferedBytes; got != 4 {
		t.Fatalf("replacement reset outstanding byte budget to %d", got)
	}
	newLease, err := controller.OpenFlow(testFlow(1, 2, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.AcceptDatagram(testDatagram(newLease, 0, "x")); !errors.Is(err, ErrBufferBudget) {
		t.Fatalf("replacement bypassed outstanding byte budget: %v", err)
	}
	retained.Release()
	accepted, err := controller.AcceptDatagram(testDatagram(newLease, 1, "x"))
	if err != nil {
		t.Fatal(err)
	}
	accepted.Release()
}

func TestRegistryEnforcesCapturedUDPV2PayloadBudget(t *testing.T) {
	tests := []struct {
		name     string
		local    string
		remote   string
		expected map[int]int
	}{
		{
			name: "ipv4", local: "10.0.0.2:40000", remote: "203.0.113.9:27015",
			expected: map[int]int{1232: 1100, 1352: 1220, 1452: 1320},
		},
		{
			name: "ipv6", local: "[2001:db8::2]:40000", remote: "[2001:db8::9]:27015",
			expected: map[int]int{1232: 1076, 1352: 1196, 1452: 1296},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, tier := range []int{1232, 1352, 1452} {
				t.Run(strconv.Itoa(tier), func(t *testing.T) {
					maximum, err := tgp.MaxCapturedUDPV2Payload(
						tier,
						netip.MustParseAddrPort(test.local).Addr(),
						netip.MustParseAddrPort(test.remote).Addr(),
					)
					if err != nil {
						t.Fatal(err)
					}
					if maximum != test.expected[tier] {
						t.Fatalf("maximum payload = %d, want %d", maximum, test.expected[tier])
					}
					registry, controller := testController(t, Limits{
						MaxTGPDatagramSize: tier,
						MaxDatagramSize:    tier - tgp.CapturedUDPV2IPv4Overhead,
					})
					commitGeneration(t, controller, 1)
					lease, err := controller.OpenFlow(testFlow(1, 1, test.local, test.remote))
					if err != nil {
						t.Fatal(err)
					}
					accepted, err := controller.AcceptDatagram(Datagram{
						FlowID: lease.FlowID, Generation: lease.Generation, LeaseNonce: lease.LeaseNonce,
						Payload: make([]byte, maximum),
					})
					if err != nil {
						t.Fatalf("maximum payload rejected: %v", err)
					}
					accepted.Release()
					if registry.Health().BufferedBytes != 0 {
						t.Fatal("maximum payload reservation was not released")
					}
					if _, err := controller.AcceptDatagram(Datagram{
						FlowID: lease.FlowID, Generation: lease.Generation, LeaseNonce: lease.LeaseNonce,
						Sequence: 1, Payload: make([]byte, maximum+1),
					}); !errors.Is(err, ErrDatagramTooLarge) {
						t.Fatalf("oversized payload error = %v", err)
					}
					if registry.Health().BufferedBytes != 0 {
						t.Fatal("oversized payload reserved buffer space")
					}
				})
			}
		})
	}
}

func TestDataPacketRateLimitChargesZeroLengthDatagrams(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry, controller := testControllerAt(t, Limits{
		MaxDatagramSize: 16, PacketsPerSecond: 1, PacketBurst: 1,
		BytesPerSecond: 100, ByteBurst: 100,
	}, &now)
	commitGeneration(t, controller, 1)
	lease, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := controller.AcceptDatagram(testDatagram(lease, 0, ""))
	if err != nil {
		t.Fatal(err)
	}
	accepted.Release()
	if _, err := controller.AcceptDatagram(testDatagram(lease, 1, "")); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("second zero-length datagram error = %v", err)
	}
	now = now.Add(time.Second)
	accepted, err = controller.AcceptDatagram(testDatagram(lease, 1, ""))
	if err != nil {
		t.Fatal(err)
	}
	accepted.Release()
	if registry.Stats().DataRateLimited != 1 {
		t.Fatalf("data rate-limited count = %d", registry.Stats().DataRateLimited)
	}
}

func TestDataByteRateLimitChargesZeroLengthDatagrams(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry, controller := testControllerAt(t, Limits{
		MaxDatagramSize: 2, PacketsPerSecond: 100, PacketBurst: 10,
		BytesPerSecond: 1, ByteBurst: 2,
	}, &now)
	commitGeneration(t, controller, 1)
	lease, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := controller.AcceptDatagram(testDatagram(lease, 0, "xx"))
	if err != nil {
		t.Fatal(err)
	}
	accepted.Release()
	if _, err := controller.AcceptDatagram(testDatagram(lease, 1, "")); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("zero-length byte charge error = %v", err)
	}
	now = now.Add(time.Second)
	accepted, err = controller.AcceptDatagram(testDatagram(lease, 1, ""))
	if err != nil {
		t.Fatal(err)
	}
	accepted.Release()
	if registry.Stats().DataRateLimited != 1 {
		t.Fatalf("data rate-limited count = %d", registry.Stats().DataRateLimited)
	}
}

func TestControlOperationRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry, controller := testControllerAt(t, Limits{
		ControlOpsPerSecond: 1, ControlBurst: 1,
	}, &now)
	transaction, err := controller.PrepareGeneration(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.AbortGeneration(transaction); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("second control operation error = %v", err)
	}
	now = now.Add(time.Second)
	if err := controller.AbortGeneration(transaction); err != nil {
		t.Fatal(err)
	}
	if registry.Stats().ControlRateLimited != 1 {
		t.Fatalf("control rate-limited count = %d", registry.Stats().ControlRateLimited)
	}
}

func TestLimitsRejectHardCapViolations(t *testing.T) {
	tests := []Limits{
		{MaxFlows: HardMaxFlows + 1},
		{MaxDatagramSize: HardMaxDatagramSize + 1},
		{MaxDatagramSize: 1024, MaxBufferedBytes: 512},
		{FlowTTL: HardMaxFlowTTL + time.Second},
		{PacketsPerSecond: HardMaxPacketsPerSecond + 1},
		{PacketBurst: HardMaxPacketBurst + 1},
		{BytesPerSecond: HardMaxBytesPerSecond + 1},
		{ByteBurst: HardMaxByteBurst + 1},
		{ControlOpsPerSecond: HardMaxControlOpsPerSecond + 1},
		{ControlBurst: HardMaxControlBurst + 1},
	}
	for _, limits := range tests {
		registry, err := NewRegistry(limits)
		if err == nil {
			_ = registry.Close()
			t.Fatalf("limits %+v unexpectedly accepted", limits)
		}
	}
}

func TestPayloadCopiesAreBudgetedOutsideLeaseState(t *testing.T) {
	_, controller := testController(t, Limits{MaxDatagramSize: 16, MaxBufferedBytes: 16})
	commitGeneration(t, controller, 1)
	lease, err := controller.OpenFlow(testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("ping")
	accepted, err := controller.AcceptDatagram(Datagram{FlowID: lease.FlowID, Generation: lease.Generation,
		LeaseNonce: lease.LeaseNonce, Sequence: 0, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Release()
	payload[0] = 'x'
	if string(accepted.Datagram.Payload) != "ping" || accepted.Datagram.Identity != lease.identity() {
		t.Fatalf("accepted datagram = %+v", accepted.Datagram)
	}
}

func testRegistry(t *testing.T, limits Limits) *Registry {
	t.Helper()
	registry, err := NewRegistry(limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return registry
}

func testController(t *testing.T, limits Limits) (*Registry, *Controller) {
	t.Helper()
	registry := testRegistry(t, limits)
	return registry, attachController(t, registry)
}

func testControllerAt(t *testing.T, limits Limits, now *time.Time) (*Registry, *Controller) {
	t.Helper()
	registry, err := newRegistry(registryOptions{
		limits: limits,
		now:    func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return registry, attachController(t, registry)
}

func attachController(t *testing.T, registry *Registry) *Controller {
	t.Helper()
	attachment, err := registry.newVerifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	token, err := registry.AttachTransport(attachment)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := registry.Authenticate(attachment, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	return controller
}

func commitGeneration(t *testing.T, controller *Controller, generation uint64) {
	t.Helper()
	transaction, err := controller.PrepareGeneration(generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.CommitGeneration(transaction); err != nil {
		t.Fatal(err)
	}
}

func testDatagram(lease FlowLease, sequence uint64, payload string) Datagram {
	return Datagram{FlowID: lease.FlowID, Generation: lease.Generation, LeaseNonce: lease.LeaseNonce,
		Sequence: sequence, Payload: []byte(payload)}
}

func testFlowID(value byte) FlowID {
	var id FlowID
	id[len(id)-1] = value
	return id
}

func testFlow(value byte, generation uint64, local, remote string) FlowSpec {
	localAddr := netip.MustParseAddrPort(local)
	remoteAddr := netip.MustParseAddrPort(remote)
	family := AddressFamilyIPv4
	if localAddr.Addr().Is6() && !localAddr.Addr().Is4In6() {
		family = AddressFamilyIPv6
	}
	return FlowSpec{ID: testFlowID(value), Generation: generation, Family: family, Local: localAddr, Remote: remoteAddr}
}
