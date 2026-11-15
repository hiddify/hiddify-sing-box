// Package mtusearch finds the largest packet that gets through a tunnel's path, for MTU discovery
// in the WireGuard and AmneziaWG transports. The transport sends the probes (ICMP echo requests
// of a given size through the tunnel); this package picks the sizes and the timeouts.
//
// The smallest size is sent first, again each second until it is answered: the first ones may go
// before the device is up or the handshake is done. Then the configured MTU is tried, which gets
// through on most paths, and the search ends there. Otherwise a binary search over the sizes in
// steps of 16 (WireGuard pads packets to that) finds the largest one that gets through. Each try
// waits four round trips of the first answer, between 300 ms and a second.
//
// An echo request is lost for other reasons than its size: the target and the routers on the way
// answer only so many a second, and a busy tunnel drops packets. All the sizes used to go out at
// once, and of a burst of fifty some were always lost; the largest answered then made the MTU,
// which came out anywhere from 1120 to 1408 on a path that carried 1420, and the endpoint closed
// its connections each time. So a try sends the size it asks about together with the smallest
// size, which tells "this size does not get through" (the smallest is answered and it is not)
// from a try that tells nothing (neither is answered), and a size is taken as too large only
// after lostTries such tries. The size goes first, so a target that answers one request of a
// pair spends it on the size. Tries are at least tryGap apart.
package mtusearch

import (
	"context"
	"time"
)

const (
	MinIPv4      = 576  // the smallest MTU of IPv4
	MinIPv6      = 1280 // and of IPv6
	step         = 16
	firstTimeout = 15 * time.Second
	maxTimeout   = time.Second
	minTimeout   = 300 * time.Millisecond
	lostTries    = 3 // tries in which a size is lost and the smallest is not, before it counts as too large
	maxTries     = 8 // tries of one size in all
)

// tryGap is the least time from one try to the next; a test makes it 0.
var tryGap = 50 * time.Millisecond

// Round sends one probe of each size at once, in that order, and returns the largest size
// answered within timeout, or 0. It may return early once the largest is answered.
type Round func(ctx context.Context, sizes []int, timeout time.Duration) int

// Search returns the largest size from smallest to configured that gets through, or 0 when the
// smallest gets no answer within 15 seconds (or ctx ends). before is called before each try of
// the smallest size, with first set on the first try (to start a handshake, say).
func Search(ctx context.Context, smallest, configured int, before func(first bool), round Round) int {
	if configured < smallest {
		return 0
	}
	answered := 0
	timeout := maxTimeout
	for deadline, first := time.Now().Add(firstTimeout), true; answered == 0 && time.Now().Before(deadline) && ctx.Err() == nil; first = false {
		if before != nil {
			before(first)
		}
		sent := time.Now()
		answered = round(ctx, []int{smallest}, maxTimeout)
		timeout = min(maxTimeout, max(minTimeout, 4*time.Since(sent)))
	}
	if answered == 0 || ctx.Err() != nil {
		return 0
	}
	search := searcher{ctx: ctx, smallest: smallest, timeout: timeout, round: round}
	// the sizes tried: the smallest, the multiples of step above it, and the configured MTU
	sizes := []int{smallest}
	for size := (smallest/step + 1) * step; size < configured; size += step {
		sizes = append(sizes, size)
	}
	if configured > smallest {
		sizes = append(sizes, configured)
	}
	low, high := 0, len(sizes) // sizes[low] gets through; sizes[high] and above do not
	if fits, known := search.fits(sizes[len(sizes)-1]); !known {
		return 0 // the path stopped answering
	} else if fits {
		return configured
	}
	high = len(sizes) - 1
	for high-low > 1 {
		middle := (low + high) / 2
		fits, known := search.fits(sizes[middle])
		if !known {
			break // the path stopped answering: what is known to get through
		}
		if fits {
			low = middle
		} else {
			high = middle
		}
	}
	if ctx.Err() != nil {
		return 0
	}
	return sizes[low]
}

type searcher struct {
	ctx      context.Context
	smallest int
	timeout  time.Duration
	round    Round
	last     time.Time // when the last try began
}

// fits tries size until it is answered, or lost lostTries times while the smallest size is
// answered. known is false when no try told anything.
func (s *searcher) fits(size int) (fits bool, known bool) {
	lost := 0
	for range maxTries {
		if wait := tryGap - time.Since(s.last); wait > 0 {
			select {
			case <-time.After(wait):
			case <-s.ctx.Done():
			}
		}
		if s.ctx.Err() != nil {
			return false, false
		}
		s.last = time.Now()
		switch s.round(s.ctx, []int{size, s.smallest}, s.timeout) {
		case size:
			return true, true
		case s.smallest:
			lost++
			if lost == lostTries {
				return false, true
			}
		}
	}
	return false, lost > 0
}
