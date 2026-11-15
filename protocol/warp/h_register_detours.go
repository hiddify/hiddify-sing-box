package warp

import (
	"context"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	N "github.com/sagernet/sing/common/network"
)

// A device that cannot be registered over its own detour is registered through any outbound
// that reaches the WARP API (withWARPAPI). With keep top most of the profile's proxies rest:
// lazy, closed, and put back to rest, which cuts a dial under way, whenever the pick changes. The
// ones that answer their ping are the likely ways in, so they are tried first, fastest first, and
// each one is held awake for its attempt (adapter.HeldLazy): created if it rests, never closed
// under the registration, and back to rest after it, as for any lazy outbound left idle.

// registerDetours are outbounds in the order to register through: the ones with a ping, by
// their delay, then the others in their own order.
func registerDetours(ctx context.Context, outbounds []adapter.Outbound) []adapter.Outbound {
	var histories map[string]*adapter.URLTestHistory
	if monitor := monitoring.Get(ctx); monitor != nil {
		histories = monitor.OutboundsHistory("") // every outbound, the ones that rest too
	}
	return byPing(outbounds, histories)
}

// byPing orders outbounds by their ping in histories: the ones with one first, the fastest
// first, then the others as they were.
func byPing(outbounds []adapter.Outbound, histories map[string]*adapter.URLTestHistory) []adapter.Outbound {
	if len(histories) == 0 {
		return outbounds
	}
	ping := func(outbound adapter.Outbound) uint16 {
		history := histories[outbound.Tag()]
		switch {
		case history == nil:
			return 0
		case history.Delay > 0:
			return history.Delay
		default:
			return history.LastGood // failed its last test, but answered before
		}
	}
	ordered := slices.Clone(outbounds)
	slices.SortStableFunc(ordered, func(a, b adapter.Outbound) int {
		pingA, pingB := ping(a), ping(b)
		switch {
		case pingA == pingB:
			return 0
		case pingA == 0:
			return 1
		case pingB == 0:
			return -1
		case pingA < pingB:
			return -1
		default:
			return 1
		}
	})
	return ordered
}

// registerThrough calls register with outbound, held awake meanwhile when it is lazy.
func registerThrough(outbound adapter.Outbound, register func(dialer N.Dialer) error) error {
	if lazy, isLazy := outbound.(adapter.HeldLazy); isLazy {
		_, release, err := lazy.Hold()
		if err != nil {
			return err
		}
		defer release()
	}
	return register(outbound)
}
