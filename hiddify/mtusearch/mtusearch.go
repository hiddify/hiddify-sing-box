// Package mtusearch finds the largest packet that gets through a tunnel's path, for MTU discovery
// in the WireGuard and AmneziaWG transports. The transport sends the probes (ICMP echo requests
// of a given size through the tunnel); this package picks the sizes and the timeouts.
//
// The smallest size is sent first, again each second until it is answered: the first ones may go
// before the device is up or the handshake is done. Then every size from it to the configured
// MTU, in steps of 16 (WireGuard pads packets to that), goes out at once, twice at most, and the
// largest answered wins. Those rounds wait four round trips of the first answer, between 300 ms
// and a second.
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
	rounds       = 2
)

// Round sends one probe of each size at once and returns the largest size answered within
// timeout, or 0. It may return early once the largest is answered.
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
	working := smallest
	for range rounds {
		var sizes []int
		for size := (working/step + 1) * step; size < configured; size += step {
			sizes = append(sizes, size)
		}
		if working < configured {
			sizes = append(sizes, configured)
		}
		if len(sizes) == 0 {
			break
		}
		working = max(working, round(ctx, sizes, timeout))
		if working == configured || ctx.Err() != nil {
			break
		}
	}
	if ctx.Err() != nil {
		return 0
	}
	return working
}
