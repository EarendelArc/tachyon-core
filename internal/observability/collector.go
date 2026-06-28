package observability

import (
	"runtime"
	"sync/atomic"
)

// PipelineStats is the interface the pipeline exposes for telemetry collection.
type PipelineStats interface {
	PacketsRead() uint64
	BytesRead() uint64
	BytesTGP() uint64
	BytesDirect() uint64
	BytesDrop() uint64
	Unsupported() uint64
	LookupErrors() uint64
	DecidedTGP() uint64
	DecidedDirect() uint64
	DecidedDrop() uint64
	HandlerErrors() uint64
}

// SessionCounter reports the current number of active TGP sessions.
type SessionCounter interface {
	ActiveSessions() int
	SessionBytesSent() uint64
	SessionBytesReceived() uint64
}

// Collector gathers telemetry data from various subsystems.
type Collector struct {
	pipeline PipelineStats
	sessions SessionCounter
	seq      atomic.Uint64
}

// NewCollector creates a collector that reads from the given subsystems.
func NewCollector(pipeline PipelineStats, sessions SessionCounter) *Collector {
	return &Collector{
		pipeline: pipeline,
		sessions: sessions,
	}
}

// Snapshot gathers current telemetry data and assigns a sequence number.
func (c *Collector) Snapshot() TelemetryData {
	var data TelemetryData
	if c.pipeline != nil {
		data.PacketsRead = c.pipeline.PacketsRead()
		data.BytesRead = c.pipeline.BytesRead()
		data.BytesTGP = c.pipeline.BytesTGP()
		data.BytesDirect = c.pipeline.BytesDirect()
		data.BytesDrop = c.pipeline.BytesDrop()
		data.Unsupported = c.pipeline.Unsupported()
		data.LookupErrors = c.pipeline.LookupErrors()
		data.DecidedTGP = c.pipeline.DecidedTGP()
		data.DecidedDirect = c.pipeline.DecidedDirect()
		data.DecidedDrop = c.pipeline.DecidedDrop()
		data.HandlerErrors = c.pipeline.HandlerErrors()
	}
	if c.sessions != nil {
		data.TGPSessions = c.sessions.ActiveSessions()
		data.TGPBytesSent = c.sessions.SessionBytesSent()
		data.TGPBytesReceived = c.sessions.SessionBytesReceived()
	}
	data.Goroutines = runtime.NumGoroutine()
	return data
}

// NextSeq returns the next monotonically increasing sequence number.
func (c *Collector) NextSeq() uint64 {
	return c.seq.Add(1)
}
