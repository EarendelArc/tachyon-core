package capturedudp

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestUnverifiedTransportCannotAuthenticateOrBecomeReady(t *testing.T) {
	registry := testRegistry(t, Limits{})
	attachment := NewUnverifiedTransportAttachment("pending-pipe")
	if _, err := registry.AttachTransport(attachment); !errors.Is(err, ErrTransportNotVerified) {
		t.Fatalf("attach unverified transport error = %v", err)
	}
	health := registry.Health()
	if health.Ready || !health.TransportAttached || health.TransportPeerVerified || health.ControllerConnected {
		t.Fatalf("unverified transport health = %+v", health)
	}
	if _, err := registry.Authenticate(attachment.ID, SessionToken{}); !errors.Is(err, ErrTransportNotVerified) {
		t.Fatalf("authenticate unverified transport error = %v", err)
	}
}

func TestControllerIsSingleUseBoundAndDisconnectRevokesState(t *testing.T) {
	registry := testRegistry(t, Limits{})
	token, err := registry.AttachTransport(verifiedTransportAttachment("pipe-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Authenticate("pipe-2", token); !errors.Is(err, ErrTransportMismatch) {
		t.Fatalf("cross-transport authentication error = %v", err)
	}
	controller, err := registry.Authenticate("pipe-1", token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Authenticate("pipe-1", token); !errors.Is(err, ErrControllerActive) {
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
	controller := attachController(t, registry, "ttl-pipe")
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

func TestLimitsRejectHardCapViolations(t *testing.T) {
	tests := []Limits{
		{MaxFlows: HardMaxFlows + 1},
		{MaxDatagramSize: HardMaxDatagramSize + 1},
		{MaxDatagramSize: 1024, MaxBufferedBytes: 512},
		{FlowTTL: HardMaxFlowTTL + time.Second},
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
	return registry, attachController(t, registry, "verified-test-transport")
}

func attachController(t *testing.T, registry *Registry, attachmentID string) *Controller {
	t.Helper()
	token, err := registry.AttachTransport(verifiedTransportAttachment(attachmentID))
	if err != nil {
		t.Fatal(err)
	}
	controller, err := registry.Authenticate(attachmentID, token)
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
