package helper

import (
	"encoding/binary"
	"math/bits"
	"math/rand"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	modelCaptured int32 = iota + 1
	modelDequeued
	modelCompleting
	modelCompleted
	modelCancelled
)

// packetOwnershipModel mirrors the kernel packet rules without WDK types. The
// pending owner starts with one reference; dequeue and completion paths acquire
// local references, and exactly one CAS winner performs the terminal release.
type packetOwnershipModel struct {
	mu       sync.Mutex
	state    atomic.Int32
	refs     atomic.Int32
	pending  bool
	queued   bool
	terminal atomic.Int32
	freed    atomic.Int32
}

func newPacketOwnershipModel() *packetOwnershipModel {
	model := &packetOwnershipModel{pending: true, queued: true}
	model.state.Store(modelCaptured)
	model.refs.Store(1)
	return model
}

func (model *packetOwnershipModel) reference() { model.refs.Add(1) }

func (model *packetOwnershipModel) dereference() {
	if remaining := model.refs.Add(-1); remaining < 0 {
		panic("packet reference underflow")
	} else if remaining == 0 {
		model.freed.Add(1)
	}
}

func (model *packetOwnershipModel) dequeue(outputTooSmall bool) {
	model.mu.Lock()
	if !model.queued || !model.state.CompareAndSwap(modelCaptured, modelDequeued) {
		model.mu.Unlock()
		return
	}
	model.queued = false
	model.reference()
	model.mu.Unlock()
	if outputTooSmall {
		model.complete(modelCompleted, true)
		return
	}
	model.dereference()
}

func (model *packetOwnershipModel) complete(terminal int32, useDequeuedReference bool) {
	model.mu.Lock()
	won := model.state.CompareAndSwap(modelCaptured, modelCompleting)
	if !won {
		won = model.state.CompareAndSwap(modelDequeued, modelCompleting)
	}
	if !won {
		model.mu.Unlock()
		if useDequeuedReference {
			model.dereference()
		}
		return
	}
	if !useDequeuedReference {
		model.reference()
	}
	if model.queued {
		model.queued = false
	}
	if !model.pending {
		model.mu.Unlock()
		panic("completion won without pending ownership")
	}
	model.pending = false
	model.mu.Unlock()

	model.dereference() // pending owner
	if !model.state.CompareAndSwap(modelCompleting, terminal) {
		panic("terminal transition lost after completion ownership won")
	}
	model.terminal.Add(1)
	model.dereference() // local completion/dequeue reference
}

func TestWFPPacketOwnershipLinearizesEveryTerminalRace(t *testing.T) {
	for iteration := range 2000 {
		model := newPacketOwnershipModel()
		operations := []func(){
			func() { model.dequeue(false) },
			func() { model.dequeue(true) },
			func() { model.complete(modelCompleted, false) }, // verdict
			func() { model.complete(modelCompleted, false) }, // timeout
			func() { model.complete(modelCancelled, false) }, // flush
		}
		rand.New(rand.NewSource(int64(iteration)+1)).Shuffle(len(operations), func(i, j int) {
			operations[i], operations[j] = operations[j], operations[i]
		})
		var group sync.WaitGroup
		for _, operation := range operations {
			group.Add(1)
			go func(run func()) { defer group.Done(); run() }(operation)
		}
		group.Wait()
		model.complete(modelCancelled, false)
		if terminal, refs, freed := model.terminal.Load(), model.refs.Load(), model.freed.Load(); terminal != 1 || refs != 0 || freed != 1 {
			t.Fatalf("iteration %d: terminal=%d refs=%d freed=%d state=%d", iteration, terminal, refs, freed, model.state.Load())
		}
		if state := model.state.Load(); state != modelCompleted && state != modelCancelled {
			t.Fatalf("iteration %d: non-terminal state %d", iteration, state)
		}
	}
}

func TestWFPPacketOutputTooSmallOwnsSingleTerminalRelease(t *testing.T) {
	model := newPacketOwnershipModel()
	model.dequeue(true)
	if model.state.Load() != modelCompleted || model.terminal.Load() != 1 || model.refs.Load() != 0 || model.freed.Load() != 1 {
		t.Fatalf("output-too-small ownership did not terminate exactly once: state=%d terminal=%d refs=%d freed=%d",
			model.state.Load(), model.terminal.Load(), model.refs.Load(), model.freed.Load())
	}
}

func modelClassifyDecision(upstream uint32, hasWriteRight, capture bool) uint32 {
	if !hasWriteRight {
		return upstream
	}
	if capture {
		return 2 // FWP_ACTION_BLOCK
	}
	return 1 // FWP_ACTION_PERMIT
}

func TestWFPClassifyModelNeverOverwritesAnUpstreamDecisionWithoutRights(t *testing.T) {
	for _, upstream := range []uint32{1, 2, 3, 0xdeadbeef} {
		if got := modelClassifyDecision(upstream, false, true); got != upstream {
			t.Fatalf("upstream decision %#x overwritten with %#x", upstream, got)
		}
	}
	if got := modelClassifyDecision(3, true, false); got != 1 {
		t.Fatalf("writable fail-open decision = %d", got)
	}
	if got := modelClassifyDecision(1, true, true); got != 2 {
		t.Fatalf("writable capture decision = %d", got)
	}
}

type modelFileSession struct{ negotiated bool }

func (session *modelFileSession) authorize(ioctl string) bool {
	if ioctl == "NEGOTIATE" {
		session.negotiated = true
		return true
	}
	return session.negotiated
}

func TestWFPPerHandleNegotiationModel(t *testing.T) {
	first, second := &modelFileSession{}, &modelFileSession{}
	for _, ioctl := range []string{"SET_POLICY", "DEQUEUE", "VERDICT"} {
		if first.authorize(ioctl) || second.authorize(ioctl) {
			t.Fatalf("%s accepted before negotiation", ioctl)
		}
	}
	if !first.authorize("NEGOTIATE") || !first.authorize("SET_POLICY") || second.authorize("DEQUEUE") {
		t.Fatal("negotiation state leaked across file handles")
	}
}

type modelSessionGenerationGate struct {
	mu          sync.Mutex
	condition   *sync.Cond
	next        uint64
	active      uint64
	ownerOpen   bool
	outstanding int
}

type modelGenerationSession struct {
	gate       *modelSessionGenerationGate
	generation uint64
	negotiated bool
	closing    bool
}

func newModelSessionGenerationGate() *modelSessionGenerationGate {
	gate := &modelSessionGenerationGate{}
	gate.condition = sync.NewCond(&gate.mu)
	return gate
}

func (gate *modelSessionGenerationGate) open() *modelGenerationSession {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.ownerOpen {
		return nil
	}
	gate.next++
	gate.ownerOpen = true
	return &modelGenerationSession{gate: gate, generation: gate.next}
}

func (session *modelGenerationSession) negotiate() bool {
	gate := session.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if session.closing || !gate.ownerOpen {
		return false
	}
	session.negotiated = true
	gate.active = session.generation
	return true
}

func (session *modelGenerationSession) acquire() bool {
	gate := session.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if session.closing || !session.negotiated || gate.active != session.generation {
		return false
	}
	gate.outstanding++
	return true
}

func (session *modelGenerationSession) commit() bool {
	gate := session.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return !session.closing && session.negotiated && gate.active == session.generation
}

func (session *modelGenerationSession) release() {
	gate := session.gate
	gate.mu.Lock()
	gate.outstanding--
	gate.condition.Broadcast()
	gate.mu.Unlock()
}

func (session *modelGenerationSession) cleanup(revoked chan<- struct{}) {
	gate := session.gate
	gate.mu.Lock()
	session.closing = true
	session.negotiated = false
	if gate.active == session.generation {
		gate.active = 0
	}
	close(revoked)
	for gate.outstanding != 0 {
		gate.condition.Wait()
	}
	gate.ownerOpen = false
	gate.mu.Unlock()
}

func TestWFPCleanupRevokesBeforeDrainAndIsolatesSuccessor(t *testing.T) {
	gate := newModelSessionGenerationGate()
	first := gate.open()
	if first == nil || !first.negotiate() || !first.acquire() {
		t.Fatal("failed to establish first modeled session")
	}
	revoked := make(chan struct{})
	cleaned := make(chan struct{})
	go func() {
		first.cleanup(revoked)
		close(cleaned)
	}()
	<-revoked
	if first.commit() {
		t.Fatal("revoked session committed while cleanup waited for its rundown reference")
	}
	if successor := gate.open(); successor != nil {
		t.Fatal("successor opened before the revoked session drained")
	}
	select {
	case <-cleaned:
		t.Fatal("cleanup did not wait for the outstanding operation")
	default:
	}
	first.release()
	<-cleaned
	second := gate.open()
	if second == nil || second.generation == first.generation || !second.negotiate() || !second.acquire() || !second.commit() {
		t.Fatal("successor did not receive an isolated active generation")
	}
	second.release()
	if first.acquire() {
		t.Fatal("old pending I/O reacquired the successor session")
	}
}

type modelPrivateStatistics struct {
	captured, permitted, dropped, injected int64
	selfInjected, queueOverflow            int64
	verdictTimeout, rejectedFrames         int64
}

func TestWFPPrivateStatisticsModelRequiresEightByteAlignment(t *testing.T) {
	typeInfo := reflect.TypeOf(modelPrivateStatistics{})
	if typeInfo.Align() < 8 {
		t.Fatalf("private statistics alignment = %d", typeInfo.Align())
	}
	for index := 0; index < typeInfo.NumField(); index++ {
		if field := typeInfo.Field(index); field.Offset%8 != 0 {
			t.Fatalf("counter %s offset = %d", field.Name, field.Offset)
		}
	}
}

type modelCaptureSnapshot struct {
	sessionGeneration uint64
	policyGeneration  uint64
	lease             [16]byte
}

type modelCaptureLinearizer struct {
	mu               sync.Mutex
	activeSession    uint64
	policyGeneration uint64
	lease            [16]byte
	captureEnabled   bool
	queue            []modelCaptureSnapshot
}

func (linearizer *modelCaptureLinearizer) snapshot() (modelCaptureSnapshot, bool) {
	linearizer.mu.Lock()
	defer linearizer.mu.Unlock()
	if !linearizer.captureEnabled || linearizer.activeSession == 0 || linearizer.policyGeneration == 0 {
		return modelCaptureSnapshot{}, false
	}
	return modelCaptureSnapshot{
		sessionGeneration: linearizer.activeSession,
		policyGeneration:  linearizer.policyGeneration,
		lease:             linearizer.lease,
	}, true
}

func (linearizer *modelCaptureLinearizer) commit(snapshot modelCaptureSnapshot) bool {
	linearizer.mu.Lock()
	defer linearizer.mu.Unlock()
	if !linearizer.captureEnabled || linearizer.activeSession != snapshot.sessionGeneration ||
		linearizer.policyGeneration != snapshot.policyGeneration || linearizer.lease != snapshot.lease {
		return false
	}
	linearizer.queue = append(linearizer.queue, snapshot)
	return true
}

func runDelayedModelClassify(linearizer *modelCaptureLinearizer, captured chan<- struct{}, resume <-chan struct{}, result chan<- bool) {
	snapshot, ok := linearizer.snapshot()
	close(captured)
	<-resume
	result <- ok && linearizer.commit(snapshot)
}

func TestWFPDelayedClassifyCannotEnterSuccessorSession(t *testing.T) {
	firstLease := [16]byte{1}
	linearizer := &modelCaptureLinearizer{
		activeSession: 1, policyGeneration: 7, lease: firstLease, captureEnabled: true,
	}
	captured, resume, result := make(chan struct{}), make(chan struct{}), make(chan bool)
	go runDelayedModelClassify(linearizer, captured, resume, result)
	<-captured
	linearizer.mu.Lock()
	linearizer.activeSession = 0
	linearizer.captureEnabled = false
	linearizer.queue = nil // cleanup flushes the old session before admitting its successor
	linearizer.activeSession = 2
	linearizer.policyGeneration = 7
	linearizer.lease = firstLease
	linearizer.captureEnabled = true
	linearizer.mu.Unlock()
	close(resume)
	if <-result {
		t.Fatal("old classify committed into a successor session")
	}
	linearizer.mu.Lock()
	defer linearizer.mu.Unlock()
	if len(linearizer.queue) != 0 {
		t.Fatalf("successor queue contains %d stale captures", len(linearizer.queue))
	}
}

func TestWFPDelayedClassifyCannotRestoreReplacedPolicyGeneration(t *testing.T) {
	oldLease, newLease := [16]byte{7}, [16]byte{8}
	linearizer := &modelCaptureLinearizer{
		activeSession: 3, policyGeneration: 11, lease: oldLease, captureEnabled: true,
	}
	captured, resume, result := make(chan struct{}), make(chan struct{}), make(chan bool)
	go runDelayedModelClassify(linearizer, captured, resume, result)
	<-captured
	linearizer.mu.Lock()
	linearizer.policyGeneration = 12
	linearizer.lease = newLease
	linearizer.queue = nil // replacement flushes generation 11
	linearizer.mu.Unlock()
	close(resume)
	if <-result {
		t.Fatal("old classify committed after policy replacement")
	}
	fresh, ok := linearizer.snapshot()
	if !ok || !linearizer.commit(fresh) {
		t.Fatal("current policy classify did not commit")
	}
	linearizer.mu.Lock()
	defer linearizer.mu.Unlock()
	if len(linearizer.queue) != 1 || linearizer.queue[0].policyGeneration != 12 || linearizer.queue[0].lease != newLease {
		t.Fatalf("queue contains stale policy snapshots: %+v", linearizer.queue)
	}
}

const (
	modelUnregisterSuccess = iota
	modelUnregisterBusy
	modelUnregisterInUse
	modelUnregisterFatal
)

func modelUnregister(statuses []int, retryLimit int) bool {
	for attempt, status := range statuses {
		if attempt >= retryLimit {
			return false
		}
		switch status {
		case modelUnregisterSuccess:
			return true
		case modelUnregisterBusy, modelUnregisterInUse:
			continue
		default:
			return false
		}
	}
	return false
}

func TestWFPTeardownModelDestroysResourcesOnlyAfterUnregister(t *testing.T) {
	for name, statuses := range map[string][]int{
		"busy":   {modelUnregisterBusy, modelUnregisterSuccess},
		"in_use": {modelUnregisterInUse, modelUnregisterInUse, modelUnregisterSuccess},
	} {
		t.Run(name, func(t *testing.T) {
			if absent := modelUnregister(statuses, 4); !absent {
				t.Fatal("retryable callout never became absent")
			}
		})
	}
	if modelUnregister([]int{modelUnregisterFatal}, 4) || modelUnregister([]int{modelUnregisterBusy, modelUnregisterBusy}, 2) {
		t.Fatal("unsafe teardown reached resource destruction")
	}
}

func modelFlowStop(removePending, callbackCompletes bool) (drained, resourcesFreed bool) {
	if !removePending {
		return false, false
	}
	if !callbackCompletes {
		return false, false // bounded wait expires with ownership retained
	}
	return true, true
}

func TestWFPFlowRemovalModelBoundsWaitAndRetainsOwnership(t *testing.T) {
	if drained, freed := modelFlowStop(true, false); drained || freed {
		t.Fatal("timed-out asynchronous flow removal released callback-owned resources")
	}
	if drained, freed := modelFlowStop(true, true); !drained || !freed {
		t.Fatal("completed asynchronous flow removal did not drain")
	}
	if drained, freed := modelFlowStop(false, false); drained || freed {
		t.Fatal("failed flow removal released associated context")
	}
}

func TestWFPIPv4AndRawSendModel(t *testing.T) {
	hostAddress := uint32(0x7f000001)
	networkValue := bits.ReverseBytes32(hostAddress)
	var wire [4]byte
	binary.LittleEndian.PutUint32(wire[:], networkValue)
	if wire != [4]byte{127, 0, 0, 1} {
		t.Fatalf("IPv4 ABI bytes = %v", wire)
	}
	dataOffset, ipHeaderSize := uint32(48), uint32(20)
	if dataOffset < ipHeaderSize {
		t.Fatal("invalid raw-send fixture")
	}
	dataOffset -= ipHeaderSize // NdisRetreatNetBufferDataStart
	sendArgsPresent := false   // raw transport injection requires NULL sendArgs
	if dataOffset != 28 || sendArgsPresent {
		t.Fatal("raw-send reinjection model did not expose the IP header")
	}
}

func TestWFPPolicyReplacementModelFlushesOnlyOldGeneration(t *testing.T) {
	pending := []uint64{7, 8, 7, 9}
	oldGeneration := uint64(7)
	kept := pending[:0]
	flushed := 0
	for _, generation := range pending {
		if generation == oldGeneration {
			flushed++
			continue
		}
		kept = append(kept, generation)
	}
	if flushed != 2 || len(kept) != 2 || kept[0] != 8 || kept[1] != 9 {
		t.Fatalf("flushed=%d kept=%v", flushed, kept)
	}
}
