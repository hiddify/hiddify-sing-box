package mtusearch

import (
	"context"
	"testing"
	"time"
)

// A path that carries 1200 bytes: the search finds 1200 from 576 to 1280, in two rounds after the
// first answer.
func TestSearch(t *testing.T) {
	var calls, firsts int
	got := Search(context.Background(), MinIPv4, 1280, func(first bool) {
		if first {
			firsts++
		}
	}, func(_ context.Context, sizes []int, _ time.Duration) int {
		calls++
		best := 0
		for _, size := range sizes {
			if size <= 1200 {
				best = max(best, size)
			}
		}
		return best
	})
	if got != 1200 || calls > 3 || firsts != 1 {
		t.Fatalf("found %d in %d rounds (%d first tries)", got, calls, firsts)
	}
}

func TestSearchNoAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got := Search(ctx, MinIPv4, 1280, nil, func(context.Context, []int, time.Duration) int { return 0 }); got != 0 {
		t.Fatalf("no answer, found %d", got)
	}
	if got := Search(context.Background(), MinIPv6, 1200, nil, nil); got != 0 {
		t.Fatalf("configured below the smallest, found %d", got)
	}
}
