package helper

import (
	"encoding/binary"
	"math/bits"
	"math/rand"
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
