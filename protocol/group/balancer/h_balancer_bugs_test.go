package balancer

import (
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing/common"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Close must stop the worker; the close channel was never created, so it ran until the box context ended.
func TestH_BalancerCloseStopsWorker(t *testing.T) {
	a := newFake("a")
	ctx, _ := newBalancerCtx(t, a)
	out, err := NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("balancer"), "lb", option.BalancerOutboundOptions{Outbounds: []string{"a"}})
	require.NoError(t, err)
	lb := out.(*Balancer)
	require.NoError(t, lb.Close())
	select {
	case <-lb.close:
	case <-time.After(time.Second):
		t.Fatal("Close did not signal the worker")
	}
	require.NoError(t, lb.Close(), "a second close must not panic")
}

// A lowest-delay balancer whose members all lack a network does not panic: filterOutbounds
// falls back to every member, and the dial then fails on that member.
func TestH_BalancerLowestDelaySingleNetwork(t *testing.T) {
	tcpOnly := NewLowestDelay(outs(newFake("a", N.NetworkTCP), newFake("b", N.NetworkTCP)), option.BalancerOutboundOptions{})
	require.Equal(t, "a", tcpOnly.Now())
	tcpOnly.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(300), "b": his(30)})
	require.Equal(t, "b", tcpOnly.Now())
	require.Equal(t, "b", tcpOnly.Select(adapter.InboundContext{}, N.NetworkUDP, true).Tag())

	udpOnly := NewLowestDelay(outs(newFake("u", N.NetworkUDP)), option.BalancerOutboundOptions{})
	require.Equal(t, "u", udpOnly.Now())
}

// Now reports the member the next TCP connection goes to, so the UI shows it.
func TestH_BalancerRoundRobinNow(t *testing.T) {
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	s := NewRoundRobin(outs(a, b, c), option.BalancerOutboundOptions{DelayAcceptableRatio: 2})
	for range 4 {
		require.Equal(t, s.Select(adapter.InboundContext{}, N.NetworkTCP, false).Tag(), s.Now())
		s.Select(adapter.InboundContext{}, N.NetworkTCP, true)
	}
}

// The hashing strategies overflowed the same way when the smallest delay was a penalised cache result.
func TestH_BalancerHashingCachedDelayOverflow(t *testing.T) {
	history := map[string]*adapter.URLTestHistory{
		"a": {Delay: 5000, IsFromCache: true},
		"b": {Delay: 6000, IsFromCache: true},
	}
	consistent := NewConsistentHashing(outs(newFake("a"), newFake("b")), option.BalancerOutboundOptions{DelayAcceptableRatio: 3, MaxRetry: 3})
	consistent.UpdateOutboundsInfo(history)
	sticky := common.Must1(NewStickySession(outs(newFake("a"), newFake("b")), option.BalancerOutboundOptions{DelayAcceptableRatio: 3, MaxRetry: 3}))
	sticky.UpdateOutboundsInfo(history)
	for _, tag := range []string{"a", "b"} {
		require.True(t, consistent.Alive(newFake(tag), N.NetworkTCP), tag)
		require.True(t, sticky.Alive(newFake(tag), N.NetworkTCP), tag)
	}
}

// With keep top, a member at rest is left out of the group's history. A strategy that finds no
// member alive (none tested yet, all failed) fell back on any member, the one at rest too: it
// was created for the connection, untested, and closed under it when keep top put it away again.
func TestH_BalancerFallbackSkipsMemberAtRest(t *testing.T) {
	options := option.BalancerOutboundOptions{MaxRetry: 3, DelayAcceptableRatio: 2}
	for name, history := range map[string]map[string]*adapter.URLTestHistory{
		"untested": {"b": {}},
		"failed":   {"b": timeout()},
	} {
		members := func() []adapter.Outbound { return outs(newFake("a"), newFake("b")) } // a rests
		for strategyName, strategy := range map[string]Strategy{
			StrategyRoundRobin:        NewRoundRobin(members(), options),
			StrategyConsistentHashing: NewConsistentHashing(members(), options),
			StrategyStickySessions:    common.Must1(NewStickySession(members(), options)),
			StrategyLowestDelay:       NewLowestDelay(members(), options),
			StrategyPool:              common.Must1(NewPool(members(), options)),
		} {
			strategy.UpdateOutboundsInfo(history)
			for i := range 100 {
				metadata := adapter.InboundContext{Domain: fmt.Sprint("d", i, ".example")}
				require.Equal(t, "b", strategy.Select(metadata, N.NetworkTCP, true).Tag(), "%s, %s", name, strategyName)
			}
		}
	}
}
