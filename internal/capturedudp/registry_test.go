package capturedudp

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestRegistryAuthenticationAndClose(t *testing.T) {
	token := testToken(1)
	registry, err := NewRegistry(token[:], Limits{})
	if err != nil {
		t.Fatal(err)
	}
	wrong := testToken(2)
	if _, err := registry.Authenticate(wrong[:]); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong token error = %v, want ErrAuthentication", err)
	}
	if _, err := registry.Authenticate(token[:]); err != nil {
		t.Fatalf("authenticate correct token: %v", err)
	}
	if got := registry.Stats().AuthenticationFailures; got != 1 {
		t.Fatalf("authentication failures = %d, want 1", got)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if registry.Health().Ready {
		t.Fatal("closed registry reported ready")
	}
	if _, err := registry.Authenticate(token[:]); !errors.Is(err, ErrClosed) {
		t.Fatalf("authenticate closed registry error = %v, want ErrClosed", err)
	}
}

func TestGenerationReplacementIsMonotonicAndEvictsFlows(t *testing.T) {
	registry, session := testRegistrySession(t, Limits{})
	if err := session.ActivateGeneration(10); err != nil {
		t.Fatal(err)
	}
	if err := session.ActivateGeneration(10); err != nil {
		t.Fatalf("idempotent activation: %v", err)
	}
	if err := session.OpenFlow(testFlow(1, 10, "10.0.0.2:40000", "203.0.113.9:27015")); err != nil {
		t.Fatal(err)
	}
	if err := session.ActivateGeneration(11); err != nil {
		t.Fatal(err)
	}
	if got := registry.Health(); got.ActiveGeneration != 11 || got.OpenFlows != 0 {
		t.Fatalf("health after replacement = %+v", got)
	}
	if err := session.ActivateGeneration(10); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale activation error = %v, want ErrStaleGeneration", err)
	}
	stats := registry.Stats()
	if stats.GenerationsActivated != 2 || stats.FlowsEvicted != 1 {
		t.Fatalf("stats after replacement = %+v", stats)
	}
}

func TestDisableGenerationIsExactAndIdempotent(t *testing.T) {
	registry, session := testRegistrySession(t, Limits{})
	if err := session.ActivateGeneration(7); err != nil {
		t.Fatal(err)
	}
	if err := session.DisableGeneration(6); !errors.Is(err, ErrGenerationNotActive) {
		t.Fatalf("wrong generation disable error = %v", err)
	}
	if err := session.DisableGeneration(7); err != nil {
		t.Fatal(err)
	}
	if err := session.DisableGeneration(7); err != nil {
		t.Fatalf("idempotent disable: %v", err)
	}
	if got := registry.Health().ActiveGeneration; got != 0 {
		t.Fatalf("active generation = %d, want 0", got)
	}
}

func TestOpenFlowRejectsDuplicateIdentityAndAmbiguousTuple(t *testing.T) {
	_, session := testRegistrySession(t, Limits{MaxFlows: 2})
	if err := session.ActivateGeneration(1); err != nil {
		t.Fatal(err)
	}
	first := testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015")
	if err := session.OpenFlow(first); err != nil {
		t.Fatal(err)
	}
	if err := session.OpenFlow(first); !errors.Is(err, ErrDuplicateFlow) {
		t.Fatalf("duplicate flow error = %v", err)
	}
	ambiguous := first
	ambiguous.ID = testFlowID(2)
	if err := session.OpenFlow(ambiguous); !errors.Is(err, ErrAmbiguousTuple) {
		t.Fatalf("ambiguous tuple error = %v", err)
	}
	second := testFlow(2, 1, "10.0.0.2:40001", "203.0.113.9:27015")
	if err := session.OpenFlow(second); err != nil {
		t.Fatal(err)
	}
	third := testFlow(3, 1, "10.0.0.2:40002", "203.0.113.9:27015")
	if err := session.OpenFlow(third); !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("flow limit error = %v", err)
	}
}

func TestAcceptDatagramBindsLeaseAndRejectsReplay(t *testing.T) {
	registry, session := testRegistrySession(t, Limits{MaxDatagramSize: 4})
	if err := session.ActivateGeneration(3); err != nil {
		t.Fatal(err)
	}
	spec := testFlow(1, 3, "10.0.0.2:40000", "203.0.113.9:27015")
	if err := session.OpenFlow(spec); err != nil {
		t.Fatal(err)
	}
	payload := []byte("ping")
	got, err := session.AcceptDatagram(Datagram{FlowID: spec.ID, Generation: 3, Sequence: 0, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 'x'
	if string(got.Payload) != "ping" || got.LocalAddrPort() != spec.Local || got.RemoteAddrPort() != spec.Remote {
		t.Fatalf("accepted datagram = %+v", got)
	}
	if _, err := session.AcceptDatagram(Datagram{FlowID: spec.ID, Generation: 3, Sequence: 0}); !errors.Is(err, ErrSequenceReplay) {
		t.Fatalf("replayed sequence error = %v", err)
	}
	if _, err := session.AcceptDatagram(Datagram{FlowID: spec.ID, Generation: 3, Sequence: 1, Payload: []byte("large")}); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversized datagram error = %v", err)
	}
	if got := registry.Stats().DatagramsAccepted; got != 1 {
		t.Fatalf("accepted datagrams = %d, want 1", got)
	}
}

func TestResolveReplyAndCloseFlow(t *testing.T) {
	_, session := testRegistrySession(t, Limits{})
	if err := session.ActivateGeneration(5); err != nil {
		t.Fatal(err)
	}
	spec := testFlow(1, 5, "[2001:db8::2]:40000", "[2001:db8::9]:27015")
	if err := session.OpenFlow(spec); err != nil {
		t.Fatal(err)
	}
	replyPayload := []byte("pong")
	delivery, err := session.ResolveReply(tgp.TunnelDatagram{
		LocalIP: spec.Local.Addr(), LocalPort: spec.Local.Port(),
		RemoteIP: spec.Remote.Addr(), RemotePort: spec.Remote.Port(),
		Payload: replyPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	replyPayload[0] = 'x'
	if delivery.FlowID != spec.ID || delivery.Generation != 5 || string(delivery.Payload) != "pong" {
		t.Fatalf("delivery = %+v", delivery)
	}
	if err := session.CloseFlow(5, spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := session.ResolveReply(tgp.TunnelDatagram{
		LocalIP: spec.Local.Addr(), LocalPort: spec.Local.Port(),
		RemoteIP: spec.Remote.Addr(), RemotePort: spec.Remote.Port(),
	}); !errors.Is(err, ErrUnknownFlow) {
		t.Fatalf("reply after close error = %v", err)
	}
}

func TestFlowValidationRejectsFamilyMismatch(t *testing.T) {
	_, session := testRegistrySession(t, Limits{})
	if err := session.ActivateGeneration(1); err != nil {
		t.Fatal(err)
	}
	spec := testFlow(1, 1, "10.0.0.2:40000", "203.0.113.9:27015")
	spec.Family = AddressFamilyIPv6
	if err := session.OpenFlow(spec); !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("family mismatch error = %v", err)
	}
}

func testRegistrySession(t *testing.T, limits Limits) (*Registry, *Session) {
	t.Helper()
	token := testToken(7)
	registry, err := NewRegistry(token[:], limits)
	if err != nil {
		t.Fatal(err)
	}
	session, err := registry.Authenticate(token[:])
	if err != nil {
		t.Fatal(err)
	}
	return registry, session
}

func testToken(value byte) [SessionTokenSize]byte {
	var token [SessionTokenSize]byte
	for index := range token {
		token[index] = value
	}
	return token
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
	return FlowSpec{
		ID: testFlowID(value), Generation: generation, Family: family,
		Local: localAddr, Remote: remoteAddr,
	}
}
