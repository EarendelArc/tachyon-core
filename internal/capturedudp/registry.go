// Package capturedudp defines the process-agnostic trust boundary between a
// privileged platform capture helper and Tachyon Core.
//
// It intentionally contains no WFP, Wintun, PID lookup, named-pipe, or service
// implementation. Platform transports authenticate first, then use Registry
// to enforce generation-bound flow leases before forwarding datagrams to TGP.
package capturedudp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

const (
	SessionTokenSize       = 32
	defaultMaxFlows        = 4096
	defaultMaxDatagramSize = 65507
)

var (
	ErrAuthentication      = errors.New("captured UDP authentication failed")
	ErrClosed              = errors.New("captured UDP registry closed")
	ErrInvalidFlow         = errors.New("invalid captured UDP flow")
	ErrUnknownFlow         = errors.New("unknown captured UDP flow")
	ErrDuplicateFlow       = errors.New("duplicate captured UDP flow")
	ErrAmbiguousTuple      = errors.New("captured UDP tuple already owned by another flow")
	ErrInvalidGeneration   = errors.New("invalid captured UDP policy generation")
	ErrStaleGeneration     = errors.New("stale captured UDP policy generation")
	ErrGenerationNotActive = errors.New("captured UDP policy generation is not active")
	ErrSequenceReplay      = errors.New("captured UDP datagram sequence replay")
	ErrDatagramTooLarge    = errors.New("captured UDP datagram exceeds configured limit")
	ErrFlowLimit           = errors.New("captured UDP flow limit reached")
)

type FlowID [16]byte

func (id FlowID) IsZero() bool { return id == FlowID{} }

type AddressFamily uint8

const (
	AddressFamilyIPv4 AddressFamily = 4
	AddressFamilyIPv6 AddressFamily = 6
)

type Limits struct {
	MaxFlows        int
	MaxDatagramSize int
}

func (l Limits) normalized() Limits {
	if l.MaxFlows <= 0 {
		l.MaxFlows = defaultMaxFlows
	}
	if l.MaxDatagramSize <= 0 {
		l.MaxDatagramSize = defaultMaxDatagramSize
	}
	return l
}

// FlowSpec is the immutable lease installed by the authenticated helper.
// Local is the selected application's socket endpoint. Remote is the original
// destination observed before platform redirection or absorption.
type FlowSpec struct {
	ID         FlowID
	Generation uint64
	Family     AddressFamily
	Local      netip.AddrPort
	Remote     netip.AddrPort
}

type Datagram struct {
	FlowID     FlowID
	Generation uint64
	Sequence   uint64
	Payload    []byte
}

type Delivery struct {
	FlowID     FlowID
	Generation uint64
	Payload    []byte
}

type Health struct {
	Ready            bool
	ActiveGeneration uint64
	OpenFlows        int
}

type Stats struct {
	AuthenticationFailures uint64
	GenerationsActivated   uint64
	GenerationsDisabled    uint64
	FlowsOpened            uint64
	FlowsClosed            uint64
	FlowsEvicted           uint64
	DatagramsAccepted      uint64
	RepliesResolved        uint64
	Rejected               uint64
}

type flowTuple struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

type flowLease struct {
	spec        FlowSpec
	hasSequence bool
	sequence    uint64
}

// Registry owns active policy generation and flow leases for one Core process.
// All methods are safe for concurrent use.
type Registry struct {
	mu sync.Mutex

	token  [SessionTokenSize]byte
	limits Limits
	closed bool

	activeGeneration uint64
	lastGeneration   uint64
	flows            map[FlowID]*flowLease
	tuples           map[flowTuple]FlowID
	stats            Stats
}

// GenerateSessionToken returns a cryptographically random per-launch token.
func GenerateSessionToken() ([SessionTokenSize]byte, error) {
	var token [SessionTokenSize]byte
	if _, err := rand.Read(token[:]); err != nil {
		return token, fmt.Errorf("generate captured UDP session token: %w", err)
	}
	return token, nil
}

func NewRegistry(token []byte, limits Limits) (*Registry, error) {
	if len(token) != SessionTokenSize {
		return nil, fmt.Errorf("captured UDP session token must be %d bytes", SessionTokenSize)
	}
	registry := &Registry{
		limits: limits.normalized(),
		flows:  make(map[FlowID]*flowLease),
		tuples: make(map[flowTuple]FlowID),
	}
	copy(registry.token[:], token)
	return registry, nil
}

// Authenticate creates a capability object after a constant-time token check.
// A future named-pipe transport must additionally verify the peer OS identity.
func (r *Registry) Authenticate(token []byte) (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	if len(token) != SessionTokenSize || subtle.ConstantTimeCompare(r.token[:], token) != 1 {
		r.stats.AuthenticationFailures++
		return nil, ErrAuthentication
	}
	return &Session{registry: r}, nil
}

// Session is an authenticated capability for manipulating the registry. It
// does not represent a network transport and must not be serialized.
type Session struct {
	registry *Registry
}

func (s *Session) ActivateGeneration(generation uint64) error {
	if s == nil || s.registry == nil {
		return ErrAuthentication
	}
	return s.registry.activateGeneration(generation)
}

func (s *Session) DisableGeneration(generation uint64) error {
	if s == nil || s.registry == nil {
		return ErrAuthentication
	}
	return s.registry.disableGeneration(generation)
}

func (s *Session) OpenFlow(spec FlowSpec) error {
	if s == nil || s.registry == nil {
		return ErrAuthentication
	}
	return s.registry.openFlow(spec)
}

func (s *Session) CloseFlow(generation uint64, id FlowID) error {
	if s == nil || s.registry == nil {
		return ErrAuthentication
	}
	return s.registry.closeFlow(generation, id)
}

// AcceptDatagram validates helper input and returns the process-agnostic TGP
// tunnel representation. The caller remains responsible for TGP transmission.
func (s *Session) AcceptDatagram(datagram Datagram) (tgp.TunnelDatagram, error) {
	if s == nil || s.registry == nil {
		return tgp.TunnelDatagram{}, ErrAuthentication
	}
	return s.registry.acceptDatagram(datagram)
}

// ResolveReply maps a TGP response back to the helper flow lease. The current
// TGP tunnel format identifies flows by their local/remote tuple, so duplicate
// active tuples are rejected at OpenFlow.
func (s *Session) ResolveReply(datagram tgp.TunnelDatagram) (Delivery, error) {
	if s == nil || s.registry == nil {
		return Delivery{}, ErrAuthentication
	}
	return s.registry.resolveReply(datagram)
}

func (r *Registry) Health() Health {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Health{
		Ready:            !r.closed,
		ActiveGeneration: r.activeGeneration,
		OpenFlows:        len(r.flows),
	}
}

func (r *Registry) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.stats.FlowsEvicted += uint64(len(r.flows))
	r.clearFlowsLocked()
	r.activeGeneration = 0
	clear(r.token[:])
	r.closed = true
	return nil
}

func (r *Registry) activateGeneration(generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if generation == 0 {
		r.stats.Rejected++
		return ErrInvalidGeneration
	}
	if generation == r.activeGeneration {
		return nil
	}
	if generation <= r.lastGeneration {
		r.stats.Rejected++
		return ErrStaleGeneration
	}
	r.stats.FlowsEvicted += uint64(len(r.flows))
	r.clearFlowsLocked()
	r.activeGeneration = generation
	r.lastGeneration = generation
	r.stats.GenerationsActivated++
	return nil
}

func (r *Registry) disableGeneration(generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if generation == 0 {
		r.stats.Rejected++
		return ErrInvalidGeneration
	}
	if r.activeGeneration == 0 && generation == r.lastGeneration {
		return nil
	}
	if generation != r.activeGeneration {
		r.stats.Rejected++
		return ErrGenerationNotActive
	}
	r.stats.FlowsEvicted += uint64(len(r.flows))
	r.clearFlowsLocked()
	r.activeGeneration = 0
	r.stats.GenerationsDisabled++
	return nil
}

func (r *Registry) openFlow(spec FlowSpec) error {
	if err := validateFlowSpec(spec); err != nil {
		r.reject()
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if spec.Generation != r.activeGeneration || r.activeGeneration == 0 {
		r.stats.Rejected++
		return ErrGenerationNotActive
	}
	if _, exists := r.flows[spec.ID]; exists {
		r.stats.Rejected++
		return ErrDuplicateFlow
	}
	if len(r.flows) >= r.limits.MaxFlows {
		r.stats.Rejected++
		return ErrFlowLimit
	}
	tuple := flowTuple{local: spec.Local, remote: spec.Remote}
	if _, exists := r.tuples[tuple]; exists {
		r.stats.Rejected++
		return ErrAmbiguousTuple
	}
	r.flows[spec.ID] = &flowLease{spec: spec}
	r.tuples[tuple] = spec.ID
	r.stats.FlowsOpened++
	return nil
}

func (r *Registry) closeFlow(generation uint64, id FlowID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if generation != r.activeGeneration || generation == 0 {
		r.stats.Rejected++
		return ErrGenerationNotActive
	}
	lease, exists := r.flows[id]
	if !exists || lease.spec.Generation != generation {
		r.stats.Rejected++
		return ErrUnknownFlow
	}
	delete(r.flows, id)
	delete(r.tuples, flowTuple{local: lease.spec.Local, remote: lease.spec.Remote})
	r.stats.FlowsClosed++
	return nil
}

func (r *Registry) acceptDatagram(datagram Datagram) (tgp.TunnelDatagram, error) {
	if len(datagram.Payload) > r.limits.MaxDatagramSize {
		r.reject()
		return tgp.TunnelDatagram{}, ErrDatagramTooLarge
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return tgp.TunnelDatagram{}, ErrClosed
	}
	if datagram.Generation != r.activeGeneration || datagram.Generation == 0 {
		r.stats.Rejected++
		return tgp.TunnelDatagram{}, ErrGenerationNotActive
	}
	lease, exists := r.flows[datagram.FlowID]
	if !exists || lease.spec.Generation != datagram.Generation {
		r.stats.Rejected++
		return tgp.TunnelDatagram{}, ErrUnknownFlow
	}
	if lease.hasSequence && datagram.Sequence <= lease.sequence {
		r.stats.Rejected++
		return tgp.TunnelDatagram{}, ErrSequenceReplay
	}
	lease.hasSequence = true
	lease.sequence = datagram.Sequence
	r.stats.DatagramsAccepted++
	return tgp.TunnelDatagram{
		LocalIP:    lease.spec.Local.Addr(),
		LocalPort:  lease.spec.Local.Port(),
		RemoteIP:   lease.spec.Remote.Addr(),
		RemotePort: lease.spec.Remote.Port(),
		Payload:    append([]byte(nil), datagram.Payload...),
	}, nil
}

func (r *Registry) resolveReply(datagram tgp.TunnelDatagram) (Delivery, error) {
	if len(datagram.Payload) > r.limits.MaxDatagramSize {
		r.reject()
		return Delivery{}, ErrDatagramTooLarge
	}
	if !datagram.LocalIP.IsValid() || !datagram.RemoteIP.IsValid() {
		r.reject()
		return Delivery{}, ErrInvalidFlow
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Delivery{}, ErrClosed
	}
	if r.activeGeneration == 0 {
		r.stats.Rejected++
		return Delivery{}, ErrGenerationNotActive
	}
	tuple := flowTuple{local: datagram.LocalAddrPort(), remote: datagram.RemoteAddrPort()}
	id, exists := r.tuples[tuple]
	if !exists {
		r.stats.Rejected++
		return Delivery{}, ErrUnknownFlow
	}
	lease, exists := r.flows[id]
	if !exists || lease.spec.Generation != r.activeGeneration {
		r.stats.Rejected++
		return Delivery{}, ErrUnknownFlow
	}
	r.stats.RepliesResolved++
	return Delivery{
		FlowID:     id,
		Generation: lease.spec.Generation,
		Payload:    append([]byte(nil), datagram.Payload...),
	}, nil
}

func (r *Registry) reject() {
	r.mu.Lock()
	r.stats.Rejected++
	r.mu.Unlock()
}

func (r *Registry) clearFlowsLocked() {
	clear(r.flows)
	clear(r.tuples)
}

func validateFlowSpec(spec FlowSpec) error {
	if spec.ID.IsZero() || spec.Generation == 0 {
		return ErrInvalidFlow
	}
	if !spec.Local.IsValid() || !spec.Remote.IsValid() || spec.Local.Port() == 0 || spec.Remote.Port() == 0 {
		return ErrInvalidFlow
	}
	if spec.Local.Addr().Is4() != spec.Remote.Addr().Is4() {
		return ErrInvalidFlow
	}
	switch spec.Family {
	case AddressFamilyIPv4:
		if !spec.Local.Addr().Is4() {
			return ErrInvalidFlow
		}
	case AddressFamilyIPv6:
		if !spec.Local.Addr().Is6() || spec.Local.Addr().Is4In6() {
			return ErrInvalidFlow
		}
	default:
		return ErrInvalidFlow
	}
	return nil
}
