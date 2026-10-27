package balancer

import (
	"testing"
	"time"

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
	sticky := NewStickySession(outs(newFake("a"), newFake("b")), option.BalancerOutboundOptions{DelayAcceptableRatio: 3, MaxRetry: 3})
	sticky.UpdateOutboundsInfo(history)
	for _, tag := range []string{"a", "b"} {
		require.True(t, consistent.Alive(newFake(tag), N.NetworkTCP), tag)
		require.True(t, sticky.Alive(newFake(tag), N.NetworkTCP), tag)
	}
}
