package firebasetunnel

import (
	"math/rand"
	"sync"
	"time"
)

// jitteredBackoff returns an exponential backoff duration (capped at 30s)
// with +/-20% jitter, to avoid thundering-herd reconnects when many
// sessions/instances share one Firebase project.
func jitteredBackoff(attempt int) time.Duration {
	base := 2 * time.Second
	max := 30 * time.Second
	d := base << uint(min(attempt-1, 4))
	if d > max || d <= 0 {
		d = max
	}
	jitter := time.Duration(rand.Int63n(int64(d) / 5)) // up to 20%
	return d - jitter/2 + time.Duration(rand.Int63n(int64(jitter)+1))
}

// tokenBucket is a simple per-second refill rate limiter used to bound
// session-creation rate per user.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	last       time.Time
}

func newTokenBucket(ratePerSecond, burst int) *tokenBucket {
	if ratePerSecond <= 0 {
		ratePerSecond = 1
	}
	if burst <= 0 {
		burst = ratePerSecond
	}
	return &tokenBucket{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: float64(ratePerSecond),
		last:       time.Now(),
	}
}

func (b *tokenBucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
