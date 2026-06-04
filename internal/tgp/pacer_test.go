package tgp_test

import (
	"context"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestTokenBucketPacer_BasicRate(t *testing.T) {
	// At 1000 pps, each token should take ~1ms.
	pacer := tgp.NewTokenBucketPacer(1000)

	ctx := context.Background()
	start := time.Now()
	const n = 5
	for i := 0; i < n; i++ {
		if err := pacer.Consume(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)

	// With depth-1 bucket, 5 tokens at 1000pps should take ≥4ms.
	// Allow generous margin for CI environment variance.
	if elapsed < 3*time.Millisecond {
		t.Errorf("consumed %d tokens in %v (too fast — pacing not working)", n, elapsed)
	}
}

func TestTokenBucketPacer_Cancellation(t *testing.T) {
	// At 1pps the next token won't arrive for ~1 second.
	// Cancelling the context should unblock immediately.
	pacer := tgp.NewTokenBucketPacer(1)
	_ = pacer.Consume(context.Background()) // consume the first token

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := pacer.Consume(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected cancellation error, got nil")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("cancellation took too long: %v", elapsed)
	}
}

func TestTokenBucketPacer_SetRate(t *testing.T) {
	pacer := tgp.NewTokenBucketPacer(100)
	pacer.SetRate(2000)
	if pacer.Rate() != 2000 {
		t.Errorf("expected rate 2000, got %f", pacer.Rate())
	}
}

func TestTokenBucketPacer_ZeroOrNegativeRate(t *testing.T) {
	// Zero/negative should default to 100 pps.
	pacer := tgp.NewTokenBucketPacer(0)
	if pacer.Rate() != 100 {
		t.Errorf("expected default 100 pps, got %f", pacer.Rate())
	}
}
