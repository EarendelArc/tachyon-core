package helper

import (
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
