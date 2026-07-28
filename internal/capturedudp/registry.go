// Package capturedudp defines the process-agnostic trust boundary between a
// privileged platform capture helper and Tachyon Core.
//
// It intentionally contains no WFP, Wintun, PID lookup, named-pipe, or service
// implementation. Until a platform transport verifies its OS peer, the
// registry cannot authenticate a controller and never reports ready.
package capturedudp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

const (
	SessionTokenSize = 32

	HardMaxFlows                = 65536
	HardMaxDatagramSize         = tgp.MaxTGPDatagramSize - tgp.CapturedUDPV2IPv4Overhead
	HardMaxBufferedBytes        = 64 << 20
	HardMaxFlowTTL              = time.Hour
	MinFlowTTL                  = time.Second
	HardMaxPacketsPerSecond     = 200000
	HardMaxPacketBurst          = 20000
	HardMaxBytesPerSecond       = 256 << 20
	HardMaxByteBurst            = 64 << 20
	HardMaxControlOpsPerSecond  = 10000
	HardMaxControlBurst         = 1000
	HardMaxOutstandingObjects   = 8192
	HardMaxObjectsPerDirection  = 4096
	HardMaxOutstandingMetadata  = 1 << 20
	HardMaxMetadataPerDirection = 768 << 10
	MinPayloadReservation       = 64
	defaultMaxFlows             = 4096
	defaultTGPDatagramSize      = tgp.DefaultTGPDatagramSize
	defaultBufferedBytes        = 8 << 20
	defaultFlowTTL              = 2 * time.Minute
	defaultReapInterval         = 30 * time.Second
	defaultPacketsPerSecond     = 20000
	defaultPacketBurst          = 2000
	defaultBytesPerSecond       = 32 << 20
	defaultByteBurst            = 8 << 20
	defaultControlOpsPerSecond  = 2000
	defaultControlBurst         = 200
	estimatedFlowMetaSize       = 256
	hardFlowMetadataBytes       = 16 << 20
	outstandingObjectMetaSize   = 160
)

var (
	ErrAuthentication       = errors.New("captured UDP authentication failed")
	ErrClosed               = errors.New("captured UDP registry closed")
	ErrInvalidFlow          = errors.New("invalid captured UDP flow")
	ErrUnknownFlow          = errors.New("unknown captured UDP flow")
	ErrDuplicateFlow        = errors.New("duplicate captured UDP flow")
	ErrInvalidGeneration    = errors.New("invalid captured UDP policy generation")
	ErrStaleGeneration      = errors.New("stale captured UDP policy generation")
	ErrGenerationNotActive  = errors.New("captured UDP policy generation is not active")
	ErrSequenceReplay       = errors.New("captured UDP datagram sequence replay")
	ErrDatagramTooLarge     = errors.New("captured UDP datagram exceeds configured limit")
	ErrFlowLimit            = errors.New("captured UDP flow limit reached")
	ErrBufferBudget         = errors.New("captured UDP buffered byte budget exhausted")
	ErrTransportNotVerified = errors.New("captured UDP transport peer is not verified")
	ErrTransportMismatch    = errors.New("captured UDP transport attachment mismatch")
	ErrTransportActive      = errors.New("captured UDP transport attachment already active")
	ErrControllerActive     = errors.New("captured UDP controller already connected")
	ErrControllerRevoked    = errors.New("captured UDP controller revoked")
	ErrTransactionActive    = errors.New("captured UDP generation transaction already prepared")
	ErrUnknownTransaction   = errors.New("unknown captured UDP generation transaction")
	ErrMissingLeaseIdentity = errors.New("captured UDP reply has no lease identity")
	ErrRateLimit            = errors.New("captured UDP controller rate limit exceeded")
	ErrAttachmentStale      = errors.New("captured UDP transport attachment is no longer usable")
	ErrOutstandingBudget    = errors.New("captured UDP outstanding object budget exhausted")
)

type FlowID = tgp.FlowID
type LeaseNonce = tgp.LeaseNonce
type SessionToken [SessionTokenSize]byte
type attachmentID [32]byte
type controllerID [16]byte
type transactionID [16]byte

type AddressFamily uint8

type attachmentState uint8

const (
	attachmentNew attachmentState = iota
	attachmentAttached
	attachmentDetached
	attachmentClosed
)

type bufferDirection uint8

const (
	bufferAccepted bufferDirection = iota
	bufferDelivery
	bufferDirectionCount
)

const (
	AddressFamilyIPv4 AddressFamily = 4
	AddressFamilyIPv6 AddressFamily = 6
)

type Limits struct {
	MaxFlows            int
	MaxTGPDatagramSize  int
	MaxDatagramSize     int
	MaxBufferedBytes    int
	FlowTTL             time.Duration
	PacketsPerSecond    int
	PacketBurst         int
	BytesPerSecond      int
	ByteBurst           int
	ControlOpsPerSecond int
	ControlBurst        int
}

func (limits Limits) normalized() (Limits, error) {
	if limits.MaxFlows <= 0 {
		limits.MaxFlows = defaultMaxFlows
	}
	if limits.MaxTGPDatagramSize <= 0 {
		limits.MaxTGPDatagramSize = defaultTGPDatagramSize
	}
	if limits.MaxTGPDatagramSize < tgp.MinTGPDatagramSize || limits.MaxTGPDatagramSize > tgp.MaxTGPDatagramSize {
		return Limits{}, fmt.Errorf("captured UDP TGP datagram size %d is outside [%d,%d]", limits.MaxTGPDatagramSize, tgp.MinTGPDatagramSize, tgp.MaxTGPDatagramSize)
	}
	maxPayload := limits.MaxTGPDatagramSize - tgp.CapturedUDPV2IPv4Overhead
	if limits.MaxDatagramSize <= 0 {
		limits.MaxDatagramSize = maxPayload
	}
	if limits.MaxBufferedBytes <= 0 {
		limits.MaxBufferedBytes = defaultBufferedBytes
	}
	if limits.FlowTTL <= 0 {
		limits.FlowTTL = defaultFlowTTL
	}
	if limits.MaxFlows > HardMaxFlows || limits.MaxFlows*estimatedFlowMetaSize > hardFlowMetadataBytes {
		return Limits{}, fmt.Errorf("captured UDP max flows %d exceeds hard metadata budget", limits.MaxFlows)
	}
	if limits.MaxDatagramSize > HardMaxDatagramSize || limits.MaxDatagramSize > maxPayload {
		return Limits{}, fmt.Errorf("captured UDP max datagram size %d exceeds v2 budget %d", limits.MaxDatagramSize, maxPayload)
	}
	minimumBufferedBytes := max(limits.MaxDatagramSize, MinPayloadReservation)
	if limits.MaxBufferedBytes > HardMaxBufferedBytes || limits.MaxBufferedBytes < minimumBufferedBytes {
		return Limits{}, fmt.Errorf("captured UDP buffered byte budget %d is outside [%d,%d]", limits.MaxBufferedBytes, minimumBufferedBytes, HardMaxBufferedBytes)
	}
	if limits.FlowTTL < MinFlowTTL || limits.FlowTTL > HardMaxFlowTTL {
		return Limits{}, fmt.Errorf("captured UDP flow TTL %s is outside [%s,%s]", limits.FlowTTL, MinFlowTTL, HardMaxFlowTTL)
	}
	if limits.PacketsPerSecond <= 0 {
		limits.PacketsPerSecond = defaultPacketsPerSecond
	}
	if limits.PacketBurst <= 0 {
		limits.PacketBurst = defaultPacketBurst
	}
	if limits.BytesPerSecond <= 0 {
		limits.BytesPerSecond = defaultBytesPerSecond
	}
	if limits.ByteBurst <= 0 {
		limits.ByteBurst = defaultByteBurst
	}
	if limits.ControlOpsPerSecond <= 0 {
		limits.ControlOpsPerSecond = defaultControlOpsPerSecond
	}
	if limits.ControlBurst <= 0 {
		limits.ControlBurst = defaultControlBurst
	}
	if limits.PacketsPerSecond > HardMaxPacketsPerSecond || limits.PacketBurst > HardMaxPacketBurst ||
		limits.BytesPerSecond > HardMaxBytesPerSecond || limits.ByteBurst > HardMaxByteBurst ||
		limits.ControlOpsPerSecond > HardMaxControlOpsPerSecond || limits.ControlBurst > HardMaxControlBurst {
		return Limits{}, errors.New("captured UDP rate limit exceeds a hard ceiling")
	}
	if limits.ByteBurst < limits.MaxDatagramSize {
		return Limits{}, fmt.Errorf("captured UDP byte burst %d is smaller than max datagram %d", limits.ByteBurst, limits.MaxDatagramSize)
	}
	return limits, nil
}

// TransportAttachment models the result of platform transport setup. The only
// public constructor creates an unverified attachment. A future named-pipe
// implementation in this package must set peerVerified only after OS-token and
// ACL verification.
type TransportAttachment struct {
	registry     *Registry
	id           attachmentID
	peerVerified bool
	state        attachmentState
}

func (attachment *TransportAttachment) Detach() error {
	if attachment == nil || attachment.registry == nil {
		return ErrTransportMismatch
	}
	return attachment.registry.detachTransport(attachment)
}

// FlowSpec is the immutable endpoint portion of a flow lease. LeaseNonce is
// generated internally and is never accepted from the controller.
type FlowSpec struct {
	ID         FlowID
	Generation uint64
	Family     AddressFamily
	Local      netip.AddrPort
	Remote     netip.AddrPort
}

type FlowLease struct {
	FlowID     FlowID
	Generation uint64
	LeaseNonce LeaseNonce
	ExpiresAt  time.Time
}

func (lease FlowLease) identity() tgp.TunnelIdentity {
	return tgp.TunnelIdentity{FlowID: lease.FlowID, Generation: lease.Generation, LeaseNonce: lease.LeaseNonce}
}

type Datagram struct {
	FlowID     FlowID
	Generation uint64
	LeaseNonce LeaseNonce
	Sequence   uint64
	Payload    []byte
}

type Health struct {
	Ready                 bool
	TransportAttached     bool
	TransportPeerVerified bool
	ControllerConnected   bool
	ActiveGeneration      uint64
	PreparedGeneration    uint64
	OpenFlows             int
	BufferedBytes         int
	OutstandingObjects    int
	OutstandingMetadata   int
	AcceptedOutstanding   int
	DeliveriesOutstanding int
}

type Stats struct {
	AuthenticationFailures uint64
	ControllersConnected   uint64
	ControllerDisconnects  uint64
	GenerationsPrepared    uint64
	GenerationsCommitted   uint64
	GenerationsAborted     uint64
	GenerationsDisabled    uint64
	FlowsOpened            uint64
	FlowsClosed            uint64
	FlowsEvicted           uint64
	FlowsExpired           uint64
	DatagramsAccepted      uint64
	RepliesResolved        uint64
	DataRateLimited        uint64
	ControlRateLimited     uint64
	Rejected               uint64
}

type Transaction struct {
	id         transactionID
	generation uint64
}

func (transaction Transaction) Generation() uint64 { return transaction.generation }

type flowLease struct {
	spec         FlowSpec
	nonce        LeaseNonce
	hasSequence  bool
	sequence     uint64
	lastActivity time.Time
}

type preparedGeneration struct {
	id         transactionID
	generation uint64
}

type tokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate, burst int, now time.Time) tokenBucket {
	return tokenBucket{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now}
}

func (bucket *tokenBucket) refill(now time.Time) {
	if !now.After(bucket.last) {
		return
	}
	bucket.tokens += now.Sub(bucket.last).Seconds() * bucket.rate
	if bucket.tokens > bucket.burst {
		bucket.tokens = bucket.burst
	}
	bucket.last = now
}

type Registry struct {
	mu sync.Mutex

	limits       Limits
	random       io.Reader
	now          func() time.Time
	reapInterval time.Duration
	stop         chan struct{}
	done         chan struct{}
	closed       bool

	attachment      *TransportAttachment
	token           SessionToken
	tokenIssued     bool
	controller      controllerID
	controllerAlive bool
	packetBucket    tokenBucket
	byteBucket      tokenBucket
	controlBucket   tokenBucket

	prepared            *preparedGeneration
	activeGeneration    uint64
	lastGeneration      uint64
	flows               map[FlowID]*flowLease
	bufferedBytes       int
	outstandingObjects  int
	outstandingMetadata int
	objectsByDirection  [bufferDirectionCount]int
	metadataByDirection [bufferDirectionCount]int
	stats               Stats
}

type registryOptions struct {
	limits       Limits
	random       io.Reader
	now          func() time.Time
	reapInterval time.Duration
}

func NewRegistry(limits Limits) (*Registry, error) {
	return newRegistry(registryOptions{limits: limits})
}

func newRegistry(options registryOptions) (*Registry, error) {
	limits, err := options.limits.normalized()
	if err != nil {
		return nil, err
	}
	if options.random == nil {
		options.random = rand.Reader
	}
	if options.now == nil {
		options.now = time.Now
	}
	if options.reapInterval <= 0 {
		options.reapInterval = defaultReapInterval
	}
	registry := &Registry{
		limits: limits, random: options.random, now: options.now,
		reapInterval: options.reapInterval,
		stop:         make(chan struct{}), done: make(chan struct{}),
		flows: make(map[FlowID]*flowLease),
	}
	go registry.reapLoop()
	return registry, nil
}

func (r *Registry) NewUnverifiedTransportAttachment() (*TransportAttachment, error) {
	return r.newTransportAttachment(false)
}

func (r *Registry) newVerifiedTransportAttachment() (*TransportAttachment, error) {
	return r.newTransportAttachment(true)
}

func (r *Registry) newTransportAttachment(peerVerified bool) (*TransportAttachment, error) {
	var id attachmentID
	if err := readRandom(r.random, id[:]); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	return &TransportAttachment{registry: r, id: id, peerVerified: peerVerified, state: attachmentNew}, nil
}

// AttachTransport records transport state and issues a fresh one-use token
// only for an attachment whose OS peer was verified by a platform transport.
func (r *Registry) AttachTransport(attachment *TransportAttachment) (SessionToken, error) {
	var zero SessionToken
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		if attachment != nil && attachment.registry == r && attachment.state == attachmentNew {
			r.destroyAttachmentLocked(attachment, attachmentClosed)
		}
		return zero, ErrClosed
	}
	if attachment == nil || attachment.registry != r {
		return zero, ErrTransportMismatch
	}
	if attachment.state != attachmentNew || attachment.id == (attachmentID{}) {
		return zero, ErrAttachmentStale
	}
	if !attachment.peerVerified {
		return zero, ErrTransportNotVerified
	}
	if r.attachment != nil || r.controllerAlive {
		return zero, ErrTransportActive
	}
	var token SessionToken
	if err := readRandom(r.random, token[:]); err != nil {
		return zero, err
	}
	attachment.state = attachmentAttached
	r.attachment = attachment
	r.token = token
	r.tokenIssued = true
	return token, nil
}

func (r *Registry) detachTransport(attachment *TransportAttachment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if attachment == nil || attachment.registry != r {
		return ErrTransportMismatch
	}
	if r.closed {
		if attachment.state == attachmentNew {
			r.destroyAttachmentLocked(attachment, attachmentClosed)
		}
		return ErrClosed
	}
	if attachment.state == attachmentNew {
		return ErrTransportMismatch
	}
	if attachment.state != attachmentAttached || attachment.id == (attachmentID{}) {
		return ErrAttachmentStale
	}
	if r.attachment != attachment {
		return ErrTransportMismatch
	}
	r.revokeControllerLocked(true)
	r.attachment = nil
	r.destroyAttachmentLocked(attachment, attachmentDetached)
	return nil
}

// Authenticate consumes the per-attachment token and binds the sole
// controller capability to that transport attachment.
func (r *Registry) Authenticate(attachment *TransportAttachment, token SessionToken) (*Controller, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	if attachment == nil || attachment.registry != r || r.attachment != attachment {
		r.stats.AuthenticationFailures++
		return nil, ErrTransportMismatch
	}
	if attachment.state != attachmentAttached || attachment.id == (attachmentID{}) {
		r.stats.AuthenticationFailures++
		return nil, ErrAttachmentStale
	}
	if !r.attachment.peerVerified {
		r.stats.AuthenticationFailures++
		return nil, ErrTransportNotVerified
	}
	if r.controllerAlive {
		return nil, ErrControllerActive
	}
	if !r.tokenIssued || subtle.ConstantTimeCompare(r.token[:], token[:]) != 1 {
		r.stats.AuthenticationFailures++
		return nil, ErrAuthentication
	}
	var id controllerID
	if err := readRandom(r.random, id[:]); err != nil {
		return nil, err
	}
	clear(r.token[:])
	r.tokenIssued = false
	r.controller = id
	r.controllerAlive = true
	now := r.now()
	r.packetBucket = newTokenBucket(r.limits.PacketsPerSecond, r.limits.PacketBurst, now)
	r.byteBucket = newTokenBucket(r.limits.BytesPerSecond, r.limits.ByteBurst, now)
	r.controlBucket = newTokenBucket(r.limits.ControlOpsPerSecond, r.limits.ControlBurst, now)
	r.stats.ControllersConnected++
	return &Controller{registry: r, id: id, attachment: attachment}, nil
}

type Controller struct {
	registry   *Registry
	id         controllerID
	attachment *TransportAttachment
	closeOnce  sync.Once
}

func (controller *Controller) Close() error {
	if controller == nil || controller.registry == nil {
		return nil
	}
	var err error
	controller.closeOnce.Do(func() {
		err = controller.registry.disconnectController(controller.id, controller.attachment)
	})
	return err
}

func (controller *Controller) PrepareGeneration(generation uint64) (Transaction, error) {
	if controller == nil || controller.registry == nil {
		return Transaction{}, ErrControllerRevoked
	}
	return controller.registry.prepareGeneration(controller.id, generation)
}

func (controller *Controller) CommitGeneration(transaction Transaction) error {
	if controller == nil || controller.registry == nil {
		return ErrControllerRevoked
	}
	return controller.registry.commitGeneration(controller.id, transaction)
}

func (controller *Controller) AbortGeneration(transaction Transaction) error {
	if controller == nil || controller.registry == nil {
		return ErrControllerRevoked
	}
	return controller.registry.abortGeneration(controller.id, transaction)
}

func (controller *Controller) DisableGeneration(generation uint64) error {
	if controller == nil || controller.registry == nil {
		return ErrControllerRevoked
	}
	return controller.registry.disableGeneration(controller.id, generation)
}

func (controller *Controller) OpenFlow(spec FlowSpec) (FlowLease, error) {
	if controller == nil || controller.registry == nil {
		return FlowLease{}, ErrControllerRevoked
	}
	return controller.registry.openFlow(controller.id, spec)
}

func (controller *Controller) CloseFlow(generation uint64, id FlowID, nonce LeaseNonce) error {
	if controller == nil || controller.registry == nil {
		return ErrControllerRevoked
	}
	return controller.registry.closeFlow(controller.id, generation, id, nonce)
}

func (controller *Controller) AcceptDatagram(datagram Datagram) (*AcceptedDatagram, error) {
	if controller == nil || controller.registry == nil {
		return nil, ErrControllerRevoked
	}
	return controller.registry.acceptDatagram(controller.id, datagram)
}

func (controller *Controller) ResolveReply(datagram tgp.TunnelDatagram) (*Delivery, error) {
	if controller == nil || controller.registry == nil {
		return nil, ErrControllerRevoked
	}
	return controller.registry.resolveReply(controller.id, datagram)
}

type bufferLease struct {
	registry  *Registry
	bytes     int
	metadata  int
	direction bufferDirection
	once      sync.Once
}

func (lease *bufferLease) release() {
	if lease == nil || lease.registry == nil {
		return
	}
	lease.once.Do(func() {
		lease.registry.releaseBuffer(lease.direction, lease.bytes, lease.metadata)
	})
}

type AcceptedDatagram struct {
	Datagram tgp.TunnelDatagram
	buffer   *bufferLease
}

func (datagram *AcceptedDatagram) Release() {
	if datagram != nil {
		datagram.buffer.release()
	}
}

type Delivery struct {
	FlowID     FlowID
	Generation uint64
	LeaseNonce LeaseNonce
	Payload    []byte
	buffer     *bufferLease
}

func (delivery *Delivery) Release() {
	if delivery != nil {
		delivery.buffer.release()
	}
}

func (r *Registry) Health() Health {
	r.mu.Lock()
	defer r.mu.Unlock()
	health := Health{
		TransportAttached:   r.attachment != nil,
		ControllerConnected: r.controllerAlive,
		ActiveGeneration:    r.activeGeneration,
		OpenFlows:           len(r.flows), BufferedBytes: r.bufferedBytes,
		OutstandingObjects: r.outstandingObjects, OutstandingMetadata: r.outstandingMetadata,
		AcceptedOutstanding: r.objectsByDirection[bufferAccepted], DeliveriesOutstanding: r.objectsByDirection[bufferDelivery],
	}
	if r.attachment != nil {
		health.TransportPeerVerified = r.attachment.peerVerified
	}
	if r.prepared != nil {
		health.PreparedGeneration = r.prepared.generation
	}
	health.Ready = !r.closed && health.TransportAttached && health.TransportPeerVerified &&
		health.ControllerConnected && health.ActiveGeneration != 0
	return health
}

func (r *Registry) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.revokeControllerLocked(false)
	if r.attachment != nil {
		r.destroyAttachmentLocked(r.attachment, attachmentClosed)
	}
	r.attachment = nil
	close(r.stop)
	r.mu.Unlock()
	<-r.done
	return nil
}

func (r *Registry) prepareGeneration(id controllerID, generation uint64) (Transaction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.requireControllerLocked(id); err != nil {
		return Transaction{}, err
	}
	if err := r.consumeControlLocked(r.now()); err != nil {
		return Transaction{}, err
	}
	if generation == 0 {
		r.stats.Rejected++
		return Transaction{}, ErrInvalidGeneration
	}
	if r.prepared != nil {
		return Transaction{}, ErrTransactionActive
	}
	if generation <= r.lastGeneration || generation == r.activeGeneration {
		r.stats.Rejected++
		return Transaction{}, ErrStaleGeneration
	}
	var transaction transactionID
	if err := readRandom(r.random, transaction[:]); err != nil {
		return Transaction{}, err
	}
	r.prepared = &preparedGeneration{id: transaction, generation: generation}
	r.stats.GenerationsPrepared++
	return Transaction{id: transaction, generation: generation}, nil
}

func (r *Registry) commitGeneration(id controllerID, transaction Transaction) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.requireControllerLocked(id); err != nil {
		return err
	}
	if err := r.consumeControlLocked(r.now()); err != nil {
		return err
	}
	if r.prepared == nil || r.prepared.id != transaction.id || r.prepared.generation != transaction.generation {
		r.stats.Rejected++
		return ErrUnknownTransaction
	}
	r.evictFlowsLocked(false)
	r.activeGeneration = transaction.generation
	r.lastGeneration = transaction.generation
	r.prepared = nil
	r.stats.GenerationsCommitted++
	return nil
}

func (r *Registry) abortGeneration(id controllerID, transaction Transaction) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.requireControllerLocked(id); err != nil {
		return err
	}
	if err := r.consumeControlLocked(r.now()); err != nil {
		return err
	}
	if r.prepared == nil || r.prepared.id != transaction.id || r.prepared.generation != transaction.generation {
		r.stats.Rejected++
		return ErrUnknownTransaction
	}
	r.prepared = nil
	r.stats.GenerationsAborted++
	return nil
}

func (r *Registry) disableGeneration(id controllerID, generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.requireControllerLocked(id); err != nil {
		return err
	}
	if err := r.consumeControlLocked(r.now()); err != nil {
		return err
	}
	if generation == 0 || generation != r.activeGeneration {
		r.stats.Rejected++
		return ErrGenerationNotActive
	}
	r.prepared = nil
	r.evictFlowsLocked(false)
	r.activeGeneration = 0
	r.stats.GenerationsDisabled++
	return nil
}

func (r *Registry) openFlow(id controllerID, spec FlowSpec) (FlowLease, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.requireControllerLocked(id); err != nil {
		return FlowLease{}, err
	}
	if err := r.consumeControlLocked(now); err != nil {
		return FlowLease{}, err
	}
	if err := validateFlowSpec(spec); err != nil {
		r.stats.Rejected++
		return FlowLease{}, err
	}
	r.expireFlowsLocked(now)
	if spec.Generation != r.activeGeneration || r.activeGeneration == 0 {
		r.stats.Rejected++
		return FlowLease{}, ErrGenerationNotActive
	}
	if _, exists := r.flows[spec.ID]; exists {
		r.stats.Rejected++
		return FlowLease{}, ErrDuplicateFlow
	}
	if len(r.flows) >= r.limits.MaxFlows {
		r.stats.Rejected++
		return FlowLease{}, ErrFlowLimit
	}
	var nonce LeaseNonce
	if err := readRandom(r.random, nonce[:]); err != nil {
		return FlowLease{}, err
	}
	r.flows[spec.ID] = &flowLease{spec: spec, nonce: nonce, lastActivity: now}
	r.stats.FlowsOpened++
	return FlowLease{FlowID: spec.ID, Generation: spec.Generation, LeaseNonce: nonce, ExpiresAt: now.Add(r.limits.FlowTTL)}, nil
}

func (r *Registry) closeFlow(controller controllerID, generation uint64, id FlowID, nonce LeaseNonce) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.requireControllerLocked(controller); err != nil {
		return err
	}
	if err := r.consumeControlLocked(r.now()); err != nil {
		return err
	}
	lease, exists := r.flows[id]
	if generation != r.activeGeneration || !exists || lease.spec.Generation != generation || lease.nonce != nonce {
		r.stats.Rejected++
		return ErrUnknownFlow
	}
	delete(r.flows, id)
	r.stats.FlowsClosed++
	return nil
}

func (r *Registry) acceptDatagram(controller controllerID, datagram Datagram) (*AcceptedDatagram, error) {
	now := r.now()
	r.mu.Lock()
	if err := r.requireControllerLocked(controller); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if len(datagram.Payload) > r.limits.MaxDatagramSize {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrDatagramTooLarge
	}
	if err := r.consumeDataLocked(now, len(datagram.Payload)); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	lease, exists := r.flows[datagram.FlowID]
	if !exists || r.flowExpiredLocked(datagram.FlowID, lease, now) || datagram.Generation != r.activeGeneration ||
		lease.spec.Generation != datagram.Generation || lease.nonce != datagram.LeaseNonce {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrUnknownFlow
	}
	payloadLimit, err := tgp.MaxCapturedUDPV2Payload(r.limits.MaxTGPDatagramSize, lease.spec.Local.Addr(), lease.spec.Remote.Addr())
	if err != nil || len(datagram.Payload) > payloadLimit {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrDatagramTooLarge
	}
	if lease.hasSequence && datagram.Sequence <= lease.sequence {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrSequenceReplay
	}
	buffer, err := r.reserveBufferLocked(bufferAccepted, len(datagram.Payload))
	if err != nil {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, err
	}
	lease.hasSequence = true
	lease.sequence = datagram.Sequence
	lease.lastActivity = now
	identity := tgp.TunnelIdentity{FlowID: datagram.FlowID, Generation: datagram.Generation, LeaseNonce: datagram.LeaseNonce}
	local, remote := lease.spec.Local, lease.spec.Remote
	r.stats.DatagramsAccepted++
	r.mu.Unlock()

	payload := append([]byte(nil), datagram.Payload...)
	return &AcceptedDatagram{Datagram: tgp.TunnelDatagram{
		Identity: identity, LocalIP: local.Addr(), LocalPort: local.Port(),
		RemoteIP: remote.Addr(), RemotePort: remote.Port(), Payload: payload,
	}, buffer: buffer}, nil
}

func (r *Registry) resolveReply(controller controllerID, datagram tgp.TunnelDatagram) (*Delivery, error) {
	now := r.now()
	r.mu.Lock()
	if err := r.requireControllerLocked(controller); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if len(datagram.Payload) > r.limits.MaxDatagramSize {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrDatagramTooLarge
	}
	if err := r.consumeDataLocked(now, len(datagram.Payload)); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if datagram.Identity.IsZero() {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrMissingLeaseIdentity
	}
	payloadLimit, err := tgp.MaxCapturedUDPV2Payload(r.limits.MaxTGPDatagramSize, datagram.LocalIP, datagram.RemoteIP)
	if err != nil || len(datagram.Payload) > payloadLimit {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrDatagramTooLarge
	}
	lease, exists := r.flows[datagram.Identity.FlowID]
	if !exists || r.flowExpiredLocked(datagram.Identity.FlowID, lease, now) ||
		datagram.Identity.Generation != r.activeGeneration || lease.spec.Generation != datagram.Identity.Generation ||
		lease.nonce != datagram.Identity.LeaseNonce || datagram.LocalAddrPort() != lease.spec.Local ||
		datagram.RemoteAddrPort() != lease.spec.Remote {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, ErrUnknownFlow
	}
	buffer, err := r.reserveBufferLocked(bufferDelivery, len(datagram.Payload))
	if err != nil {
		r.stats.Rejected++
		r.mu.Unlock()
		return nil, err
	}
	lease.lastActivity = now
	r.stats.RepliesResolved++
	r.mu.Unlock()

	payload := append([]byte(nil), datagram.Payload...)
	return &Delivery{FlowID: datagram.Identity.FlowID, Generation: datagram.Identity.Generation,
		LeaseNonce: datagram.Identity.LeaseNonce, Payload: payload, buffer: buffer}, nil
}

func (r *Registry) requireControllerLocked(id controllerID) error {
	if r.closed {
		return ErrClosed
	}
	if !r.controllerAlive || r.controller != id {
		return ErrControllerRevoked
	}
	return nil
}

func (r *Registry) disconnectController(id controllerID, attachment *TransportAttachment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if !r.controllerAlive || r.controller != id || attachment == nil || r.attachment != attachment ||
		attachment.state != attachmentAttached || attachment.id == (attachmentID{}) {
		return ErrControllerRevoked
	}
	r.revokeControllerLocked(true)
	r.attachment = nil
	r.destroyAttachmentLocked(attachment, attachmentDetached)
	return nil
}

func (r *Registry) destroyAttachmentLocked(attachment *TransportAttachment, state attachmentState) {
	clear(attachment.id[:])
	attachment.peerVerified = false
	attachment.state = state
}

func (r *Registry) revokeControllerLocked(countDisconnect bool) {
	if r.controllerAlive && countDisconnect {
		r.stats.ControllerDisconnects++
	}
	clear(r.token[:])
	r.tokenIssued = false
	r.controller = controllerID{}
	r.controllerAlive = false
	r.prepared = nil
	r.activeGeneration = 0
	r.evictFlowsLocked(false)
}

func (r *Registry) consumeControlLocked(now time.Time) error {
	r.controlBucket.refill(now)
	if r.controlBucket.tokens < 1 {
		r.stats.ControlRateLimited++
		r.stats.Rejected++
		return ErrRateLimit
	}
	r.controlBucket.tokens--
	return nil
}

func (r *Registry) consumeDataLocked(now time.Time, payloadSize int) error {
	byteCharge := payloadSize
	if byteCharge == 0 {
		byteCharge = 1
	}
	r.packetBucket.refill(now)
	r.byteBucket.refill(now)
	if r.packetBucket.tokens < 1 || r.byteBucket.tokens < float64(byteCharge) {
		r.stats.DataRateLimited++
		r.stats.Rejected++
		return ErrRateLimit
	}
	r.packetBucket.tokens--
	r.byteBucket.tokens -= float64(byteCharge)
	return nil
}

func (r *Registry) reserveBufferLocked(direction bufferDirection, size int) (*bufferLease, error) {
	if size < 0 || size > r.limits.MaxDatagramSize {
		return nil, ErrDatagramTooLarge
	}
	if direction >= bufferDirectionCount {
		return nil, ErrOutstandingBudget
	}
	reservedBytes := max(size, MinPayloadReservation)
	if r.bufferedBytes > r.limits.MaxBufferedBytes-reservedBytes {
		return nil, ErrBufferBudget
	}
	if r.outstandingObjects >= HardMaxOutstandingObjects ||
		r.objectsByDirection[direction] >= HardMaxObjectsPerDirection ||
		r.outstandingMetadata > HardMaxOutstandingMetadata-outstandingObjectMetaSize ||
		r.metadataByDirection[direction] > HardMaxMetadataPerDirection-outstandingObjectMetaSize {
		return nil, ErrOutstandingBudget
	}
	r.bufferedBytes += reservedBytes
	r.outstandingObjects++
	r.outstandingMetadata += outstandingObjectMetaSize
	r.objectsByDirection[direction]++
	r.metadataByDirection[direction] += outstandingObjectMetaSize
	return &bufferLease{registry: r, bytes: reservedBytes, metadata: outstandingObjectMetaSize, direction: direction}, nil
}

func (r *Registry) releaseBuffer(direction bufferDirection, reservedBytes, metadata int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if direction >= bufferDirectionCount || reservedBytes <= 0 || metadata <= 0 ||
		r.bufferedBytes < reservedBytes || r.outstandingObjects <= 0 || r.outstandingMetadata < metadata ||
		r.objectsByDirection[direction] <= 0 || r.metadataByDirection[direction] < metadata {
		panic("captured UDP buffer lease accounting underflow")
	}
	r.bufferedBytes -= reservedBytes
	r.outstandingObjects--
	r.outstandingMetadata -= metadata
	r.objectsByDirection[direction]--
	r.metadataByDirection[direction] -= metadata
}

func (r *Registry) evictFlowsLocked(expired bool) {
	count := len(r.flows)
	if count != 0 {
		if expired {
			r.stats.FlowsExpired += uint64(count)
		} else {
			r.stats.FlowsEvicted += uint64(count)
		}
	}
	clear(r.flows)
}

func (r *Registry) flowExpiredLocked(id FlowID, lease *flowLease, now time.Time) bool {
	if now.Sub(lease.lastActivity) < r.limits.FlowTTL {
		return false
	}
	delete(r.flows, id)
	r.stats.FlowsExpired++
	return true
}

func (r *Registry) expireFlowsLocked(now time.Time) {
	for id, lease := range r.flows {
		r.flowExpiredLocked(id, lease, now)
	}
}

func (r *Registry) expireFlowsAt(now time.Time) {
	r.mu.Lock()
	r.expireFlowsLocked(now)
	r.mu.Unlock()
}

func (r *Registry) reapLoop() {
	ticker := time.NewTicker(r.reapInterval)
	defer func() {
		ticker.Stop()
		close(r.done)
	}()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.expireFlowsAt(r.now())
		}
	}
}

func validateFlowSpec(spec FlowSpec) error {
	if spec.ID == (FlowID{}) || spec.Generation == 0 {
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

func readRandom(reader io.Reader, destination []byte) error {
	if _, err := io.ReadFull(reader, destination); err != nil {
		return fmt.Errorf("generate captured UDP capability: %w", err)
	}
	var aggregate byte
	for _, value := range destination {
		aggregate |= value
	}
	if aggregate == 0 {
		return errors.New("generated captured UDP capability is all zero")
	}
	return nil
}
