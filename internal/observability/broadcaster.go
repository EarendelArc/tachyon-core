package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Broadcaster manages SSE client connections and dispatches telemetry events.
type Broadcaster struct {
	collector *Collector
	logger    *slog.Logger
	version   string
	cfgPath   string
	interval  time.Duration

	mu      sync.RWMutex
	clients map[chan Event]struct{}
	closed  bool
}

// BroadcasterOptions configures the telemetry broadcaster.
type BroadcasterOptions struct {
	Collector        *Collector
	Logger           *slog.Logger
	Version          string
	ConfigPath       string
	TelemetryInterval time.Duration
}

// NewBroadcaster creates a new SSE telemetry broadcaster.
func NewBroadcaster(opts BroadcasterOptions) *Broadcaster {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := opts.TelemetryInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	return &Broadcaster{
		collector: opts.Collector,
		logger:    logger,
		version:   opts.Version,
		cfgPath:   opts.ConfigPath,
		interval:  interval,
		clients:   make(map[chan Event]struct{}),
	}
}

// Start begins the periodic telemetry collection loop. It blocks until ctx is
// cancelled.
func (b *Broadcaster) Start(ctx context.Context) {
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Close()
			return
		case <-ticker.C:
			b.collectAndBroadcast()
		}
	}
}

// Broadcast sends an event to all connected SSE clients.
func (b *Broadcaster) Broadcast(event Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	for ch := range b.clients {
		select {
		case ch <- event:
		default:
			// Drop event for slow clients rather than blocking.
		}
	}
}

// Close disconnects all clients and stops broadcasting.
func (b *Broadcaster) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.clients {
		close(ch)
		delete(b.clients, ch)
	}
}

// ClientCount returns the number of connected SSE clients.
func (b *Broadcaster) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

// ServeHTTP handles SSE connections at /v1/telemetry/sse.
func (b *Broadcaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	eventCh := make(chan Event, 64)
	b.addClient(eventCh)
	defer b.removeClient(eventCh)

	// Send hello immediately.
	hello := NewHello(b.version, b.cfgPath)
	hello.Seq = b.collector.NextSeq()
	if !writeSSE(w, flusher, hello) {
		return
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-eventCh:
			if !ok {
				return
			}
			if !writeSSE(w, flusher, event) {
				return
			}
		}
	}
}

func (b *Broadcaster) addClient(ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.clients[ch] = struct{}{}
	b.logger.Debug("telemetry client connected", "total", len(b.clients))
}

func (b *Broadcaster) removeClient(ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, ch)
	b.logger.Debug("telemetry client disconnected", "total", len(b.clients))
}

func (b *Broadcaster) collectAndBroadcast() {
	b.mu.RLock()
	if b.closed || len(b.clients) == 0 {
		b.mu.RUnlock()
		return
	}
	b.mu.RUnlock()

	snapshot := b.collector.Snapshot()
	event := NewTelemetry(snapshot)
	event.Seq = b.collector.NextSeq()
	b.Broadcast(event)
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event Event) bool {
	data, err := json.Marshal(event)
	if err != nil {
		return false
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
	flusher.Flush()
	return true
}
