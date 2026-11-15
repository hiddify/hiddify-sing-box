package warp

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hTaggedOutbound struct {
	adapter.Outbound
	tag string
}

func (o *hTaggedOutbound) Tag() string { return o.tag }

// hHeldOutbound is a lazy outbound that records whether it is held.
type hHeldOutbound struct {
	adapter.HeldLazy
	tag   string
	holds int
}

func (o *hHeldOutbound) Tag() string { return o.tag }
func (o *hHeldOutbound) Held() bool  { return o.holds > 0 }
func (o *hHeldOutbound) Hold() (adapter.Outbound, func(), error) {
	o.holds++
	return o, func() { o.holds-- }, nil
}

func hTags(outbounds []adapter.Outbound) []string {
	tags := make([]string, len(outbounds))
	for i, outbound := range outbounds {
		tags[i] = outbound.Tag()
	}
	return tags
}

// A device is registered through the outbounds that answer their ping first, the fastest first,
// also the ones that rest (their last good ping counts), then the others in their own order.
func TestH_WARPRegistersThroughThePingedFirst(t *testing.T) {
	var outbounds []adapter.Outbound
	for _, tag := range []string{"direct", "untested", "slow", "failed-now", "fast", "never"} {
		outbounds = append(outbounds, &hTaggedOutbound{tag: tag})
	}
	histories := map[string]*adapter.URLTestHistory{
		"untested":   {},
		"slow":       {Delay: 900},
		"failed-now": {LastGood: 300, Error: "timeout"},
		"fast":       {Delay: 80},
		"never":      {Error: "timeout"},
	}
	require.Equal(t, []string{"fast", "failed-now", "slow", "direct", "untested", "never"}, hTags(byPing(outbounds, histories)))
	require.Equal(t, []string{"direct", "untested", "slow", "failed-now", "fast", "never"}, hTags(outbounds), "the box's list is left as it is")
	require.Equal(t, hTags(outbounds), hTags(byPing(outbounds, nil)), "without a monitoring, the box's order")
}

// A lazy outbound is held awake while a registration goes through it, and let go after: it rests
// again as any lazy outbound left idle.
func TestH_WARPRegisterHoldsALazyOutboundAwake(t *testing.T) {
	lazy := &hHeldOutbound{tag: "resting"}
	heldDuring := false
	err := registerThrough(lazy, func(dialer N.Dialer) error {
		heldDuring = lazy.Held()
		require.Same(t, lazy, dialer)
		return nil
	})
	require.NoError(t, err)
	require.True(t, heldDuring, "held while it registers")
	require.False(t, lazy.Held(), "let go after")

	plain := &hTaggedOutbound{tag: "plain"}
	called := false
	require.NoError(t, registerThrough(plain, func(dialer N.Dialer) error { called = true; return nil }))
	require.True(t, called)
}
