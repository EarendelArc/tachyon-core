package observability

import (
	"testing"
)

type mockPipelineStats struct {
	packetsRead   uint64
	unsupported   uint64
	lookupErrors  uint64
	decidedTGP    uint64
	decidedDirect uint64
	decidedDrop   uint64
	handlerErrors uint64
}

func (m *mockPipelineStats) PacketsRead() uint64   { return m.packetsRead }
func (m *mockPipelineStats) Unsupported() uint64    { return m.unsupported }
func (m *mockPipelineStats) LookupErrors() uint64   { return m.lookupErrors }
func (m *mockPipelineStats) DecidedTGP() uint64     { return m.decidedTGP }
func (m *mockPipelineStats) DecidedDirect() uint64   { return m.decidedDirect }
func (m *mockPipelineStats) DecidedDrop() uint64     { return m.decidedDrop }
func (m *mockPipelineStats) HandlerErrors() uint64   { return m.handlerErrors }

type mockSessionCounter struct{ count int }

func (m *mockSessionCounter) ActiveSessions() int { return m.count }

func TestCollectorSnapshot(t *testing.T) {
	pipeline := &mockPipelineStats{
		packetsRead:   1000,
		unsupported:   5,
		lookupErrors:  10,
		decidedTGP:    600,
		decidedDirect: 300,
		decidedDrop:   85,
		handlerErrors: 2,
	}
	sessions := &mockSessionCounter{count: 1}
	c := NewCollector(pipeline, sessions)

	snap := c.Snapshot()
	if snap.PacketsRead != 1000 {
		t.Fatalf("expected 1000 packets, got %d", snap.PacketsRead)
	}
	if snap.Unsupported != 5 {
		t.Fatalf("expected 5 unsupported, got %d", snap.Unsupported)
	}
	if snap.DecidedTGP != 600 {
		t.Fatalf("expected 600 tgp, got %d", snap.DecidedTGP)
	}
	if snap.TGPSessions != 1 {
		t.Fatalf("expected 1 session, got %d", snap.TGPSessions)
	}
	if snap.Goroutines < 1 {
		t.Fatal("expected at least 1 goroutine")
	}
}

func TestCollectorSnapshotNilSubsystems(t *testing.T) {
	c := NewCollector(nil, nil)
	snap := c.Snapshot()
	if snap.PacketsRead != 0 {
		t.Fatalf("expected 0 packets with nil pipeline, got %d", snap.PacketsRead)
	}
	if snap.TGPSessions != 0 {
		t.Fatalf("expected 0 sessions with nil counter, got %d", snap.TGPSessions)
	}
}

func TestCollectorNextSeqMonotonic(t *testing.T) {
	c := NewCollector(nil, nil)
	first := c.NextSeq()
	second := c.NextSeq()
	third := c.NextSeq()
	if second != first+1 {
		t.Fatalf("expected seq %d, got %d", first+1, second)
	}
	if third != second+1 {
		t.Fatalf("expected seq %d, got %d", second+1, third)
	}
}
