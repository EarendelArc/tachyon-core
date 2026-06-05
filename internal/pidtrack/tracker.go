// Package pidtrack implements process-to-socket reverse lookup.
//
// Given a 5-tuple (proto, src-ip, src-port, dst-ip, dst-port) observed on the
// TUN interface, the tracker identifies which OS process opened that connection.
// This is the foundation of per-application routing decisions.
//
// Platform implementations:
//   - Linux:   /proc/net/tcp6 + /proc/<pid>/fd/ inode join
//   - macOS:   lsof -F socket lookup + ps process metadata (alpha)
//   - Windows: GetExtendedTcpTable / GetExtendedUdpTable (iphlpapi.dll)
//
// Performance notes:
//   - Results are cached for CacheTTL to avoid per-packet syscall overhead.
//   - A 2-stage retry (RetryDelay, up to MaxRetries) handles the race where
//     the connection table hasn't been updated when the first packet arrives.
package pidtrack

import (
	"context"
	"sync"
	"time"
)

// CacheTTL is how long a (socket → ProcessInfo) mapping is cached.
const CacheTTL = 100 * time.Millisecond

// RetryDelay is the pause between lookup attempts when a socket is not yet
// in the OS connection table.
const RetryDelay = 50 * time.Millisecond

// MaxRetries is the maximum number of lookup attempts before giving up.
const MaxRetries = 3

// cacheKey indexes the cache by flow key.
type cacheKey struct {
	transport Transport
	localIP   string
	localPort uint16
}

// cacheEntry holds a cached lookup result.
type cacheEntry struct {
	info    ProcessInfo
	expires time.Time
}

// Tracker wraps a Provider with an in-memory cache and retry logic.
// All public methods are safe for concurrent use.
type Tracker struct {
	provider Provider
	mu       sync.Mutex
	cache    map[cacheKey]cacheEntry
}

// New creates a Tracker using the platform-specific Provider.
func New() (*Tracker, error) {
	p, err := newProvider()
	if err != nil {
		return nil, err
	}
	return &Tracker{
		provider: p,
		cache:    make(map[cacheKey]cacheEntry),
	}, nil
}

// LookupFlow returns the process that owns the given socket.
// It retries up to MaxRetries times with RetryDelay between attempts to handle
// the race where the OS connection table is not yet updated.
//
// Returns a zero ProcessInfo and nil error if the socket cannot be found after
// all retries (e.g. a kernel-originated packet).
func (t *Tracker) LookupFlow(ctx context.Context, flow FlowKey) (ProcessInfo, error) {
	key := cacheKey{
		transport: flow.Transport,
		localIP:   flow.LocalIP,
		localPort: flow.LocalPort,
	}

	// Fast path: cache hit.
	t.mu.Lock()
	if e, ok := t.cache[key]; ok && time.Now().Before(e.expires) {
		t.mu.Unlock()
		return e.info, nil
	}
	t.mu.Unlock()

	// Slow path: OS lookup with retry.
	var info ProcessInfo
	var lastErr error
	for i := 0; i < MaxRetries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ProcessInfo{}, ctx.Err()
			case <-time.After(RetryDelay):
			}
		}
		info, lastErr = t.provider.LookupByFlow(ctx, flow)
		if lastErr == nil {
			break
		}
	}

	if lastErr != nil {
		// Not finding the socket is not an error — return zero value.
		return ProcessInfo{}, nil
	}

	// Cache the result.
	t.mu.Lock()
	t.cache[key] = cacheEntry{info: info, expires: time.Now().Add(CacheTTL)}
	t.mu.Unlock()

	return info, nil
}

// LookupPID returns full process information for a given PID.
func (t *Tracker) LookupPID(ctx context.Context, pid int) (ProcessInfo, error) {
	return t.provider.LookupPID(ctx, pid)
}

// Evict removes a cached entry for the given flow immediately.
// Call this when a socket is known to have closed.
func (t *Tracker) Evict(flow FlowKey) {
	key := cacheKey{
		transport: flow.Transport,
		localIP:   flow.LocalIP,
		localPort: flow.LocalPort,
	}
	t.mu.Lock()
	delete(t.cache, key)
	t.mu.Unlock()
}

// PurgeExpired removes all expired cache entries.
// Call this periodically (e.g. every 5 seconds) to prevent unbounded growth.
func (t *Tracker) PurgeExpired() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.cache {
		if now.After(e.expires) {
			delete(t.cache, k)
		}
	}
}
