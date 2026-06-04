// Package tgp – pacing implementation.
//
// TokenBucketPacer implements the Pacer interface using a classic token-bucket
// algorithm. The key design insight: instead of queuing packets in memory (which
// causes Bufferbloat), we block the sender goroutine until a token is available,
// letting the OS UDP buffer remain essentially empty.
//
// # Why not Hysteria 2's Brutal CC?
//
// Brutal uses explicit congestion control to aggressively fill bandwidth, which
// is excellent for TCP-like bulk transfers but terrible for games: it creates
// large in-flight queues (Bufferbloat) that introduce 20-50 ms of added latency
// and wildly variable jitter. Token-Bucket Pacing instead deliberately caps the
// send rate to just above the game's required bandwidth, keeping the link
// utilisation just high enough and queue depth near zero.
package tgp

import (
	"context"
	"sync"
	"time"
)

// TokenBucketPacer is a thread-safe token-bucket pacer.
//
//   - Bucket depth: 1 token (intentionally shallow – no burst allowed for games).
//   - Refill interval: 1 / pps seconds.
//
// Using a depth-1 bucket means the sender can never "save up" tokens and then
// burst, which is exactly the property needed for jitter control.
type TokenBucketPacer struct {
	mu       sync.Mutex
	pps      float64       // tokens per second
	interval time.Duration // derived from pps: 1s / pps
	last     time.Time     // time of the last token issue
}

// NewTokenBucketPacer creates a pacer with the given initial rate.
// pps must be > 0; a value of 0 defaults to 100 pps (typical game tick rate).
func NewTokenBucketPacer(pps float64) *TokenBucketPacer {
	if pps <= 0 {
		pps = 100
	}
	return &TokenBucketPacer{
		pps:      pps,
		interval: pacerInterval(pps),
		last:     time.Now(),
	}
}

// Consume blocks until the next token is available, respecting ctx cancellation.
// On return, the caller MAY send exactly one packet.
func (p *TokenBucketPacer) Consume(ctx context.Context) error {
	for {
		p.mu.Lock()
		now := time.Now()
		next := p.last.Add(p.interval)
		if !now.Before(next) {
			// Token available – issue it.
			p.last = now
			p.mu.Unlock()
			return nil
		}
		wait := next.Sub(now)
		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			// Re-check under lock (rate may have changed while we slept).
		}
	}
}

// SetRate updates the refill rate. Thread-safe.
func (p *TokenBucketPacer) SetRate(pps float64) {
	if pps <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pps = pps
	p.interval = pacerInterval(pps)
}

// Rate returns the current refill rate in packets-per-second.
func (p *TokenBucketPacer) Rate() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pps
}

func pacerInterval(pps float64) time.Duration {
	return time.Duration(float64(time.Second) / pps)
}

// Ensure compile-time interface satisfaction.
var _ Pacer = (*TokenBucketPacer)(nil)
