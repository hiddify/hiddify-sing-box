package mtusearch

import (
	"context"
	"math/rand/v2"
	"testing"
	"time"
)

func init() { tryGap = 0 }

// path is a tunnel's path for a test: it carries packets up to mtu, each request is lost with
// probability loss, and of the requests of a round that reach it the target answers the first
// `answers` (0: all).
type path struct {
	mtu     int
	answers int
	loss    float64
	random  *rand.Rand
	rounds  int
}

func (p *path) round(_ context.Context, sizes []int, _ time.Duration) int {
	p.rounds++
	best, answered := 0, 0
	for _, size := range sizes {
		if size > p.mtu || p.random != nil && p.random.Float64() < p.loss {
			continue // lost on the way
		}
		if p.answers > 0 && answered == p.answers {
			continue // the target answers only so many at a time
		}
		answered++
		best = max(best, size)
	}
	return best
}

// A path that carries 1200 bytes: the search finds 1200 from 576 to 1280.
func TestSearch(t *testing.T) {
	var firsts int
	carrier := &path{mtu: 1200}
	got := Search(context.Background(), MinIPv4, 1280, func(first bool) {
		if first {
			firsts++
		}
	}, carrier.round)
	if got != 1200 || firsts != 1 || carrier.rounds > 30 {
		t.Fatalf("found %d in %d rounds (%d first tries)", got, carrier.rounds, firsts)
	}
	for _, mtu := range []int{576, 592, 1008, 1264} {
		carrier := &path{mtu: mtu}
		if got := Search(context.Background(), MinIPv4, 1280, nil, carrier.round); got != mtu {
			t.Fatalf("a path of %d: found %d", mtu, got)
		}
	}
}

// Most paths carry the configured MTU: one try after the first answer finds it.
func TestSearchConfiguredGetsThrough(t *testing.T) {
	carrier := &path{mtu: 1500}
	if got := Search(context.Background(), MinIPv4, 1420, nil, carrier.round); got != 1420 {
		t.Fatalf("found %d", got)
	}
	if carrier.rounds != 2 {
		t.Fatalf("%d rounds", carrier.rounds)
	}
}

// A target that answers only a few requests at a time, as one that limits its ICMP answers, or a
// busy tunnel that drops some: the search still finds what the path carries. All sizes at once,
// the MTU came out wherever the answers happened to stop: 1120 to 1408 on a path of 1420.
func TestSearchLimitedAnswers(t *testing.T) {
	for _, mtu := range []int{1420, 1200} {
		carrier := &path{mtu: mtu, answers: 1}
		if got := Search(context.Background(), MinIPv4, 1420, nil, carrier.round); got != mtu {
			t.Fatalf("a target that answers one request at a time, on a path of %d: found %d", mtu, got)
		}
		for seed := range uint64(100) {
			carrier := &path{mtu: mtu, loss: 0.05, random: rand.New(rand.NewPCG(seed, 1))}
			if got := Search(context.Background(), MinIPv4, 1420, nil, carrier.round); got != mtu {
				t.Fatalf("5%% of the requests lost (seed %d), on a path of %d: found %d", seed, mtu, got)
			}
		}
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
	// the path stops answering after the first answer: nothing is learned, the MTU stays
	answered := false
	got := Search(context.Background(), MinIPv4, 1280, nil, func(_ context.Context, sizes []int, _ time.Duration) int {
		if !answered {
			answered = true
			return sizes[0]
		}
		return 0
	})
	if got != 0 {
		t.Fatalf("a path that stopped answering: found %d", got)
	}
}
