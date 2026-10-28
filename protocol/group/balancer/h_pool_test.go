package balancer

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func hPool(t *testing.T, options option.BalancerOutboundOptions, tags ...string) *Pool {
	members := make([]*fakeOutbound, 0, len(tags))
	for _, tag := range tags {
		members = append(members, newFake(tag))
	}
	pool, err := NewPool(outs(members...), options)
	require.NoError(t, err)
	return pool
}

func hDomain(domain string) adapter.InboundContext {
	return adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(domain, 443)}
}

// selections maps each of n domains to the member it goes to.
func hSelections(pool *Pool, n int) map[string]string {
	result := make(map[string]string, n)
	for i := range n {
		domain := fmt.Sprintf("site%d.example", i)
		result[domain] = pool.Select(hDomain(domain), N.NetworkTCP, true).Tag()
	}
	return result
}

func TestH_PoolFillsSlotsInConfigOrder(t *testing.T) {
	pool := hPool(t, option.BalancerOutboundOptions{Pool: 2}, "a", "b", "c", "d")
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(0), "b": his(300), "c": his(100), "d": his(50)})
	require.Equal(t, []string{"b", "c"}, pool.Slots(N.NetworkTCP), "a never answered; tolerance 0 keeps config order, not the fastest")
}

func TestH_PoolKeysStayWhenAnotherSlotDies(t *testing.T) {
	pool := hPool(t, option.BalancerOutboundOptions{Pool: 3}, "a", "b", "c", "d")
	all := map[string]*adapter.URLTestHistory{"a": his(100), "b": his(100), "c": his(100), "d": his(100)}
	pool.UpdateOutboundsInfo(all)
	require.Equal(t, []string{"a", "b", "c"}, pool.Slots(N.NetworkTCP))
	before := hSelections(pool, 300)

	// b dies, d takes its slot: only b's keys move, all of them to d
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(monitoring.TimeoutDelay), "c": his(100), "d": his(100)})
	require.Equal(t, []string{"a", "d", "c"}, pool.Slots(N.NetworkTCP))
	after := hSelections(pool, 300)
	for domain, member := range before {
		if member == "b" {
			require.Equal(t, "d", after[domain], domain)
		} else {
			require.Equal(t, member, after[domain], domain)
		}
	}
}

func TestH_PoolDeadSlotSpreadsAndComesBack(t *testing.T) {
	pool := hPool(t, option.BalancerOutboundOptions{Pool: 3}, "a", "b", "c")
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(100), "c": his(100)})
	before := hSelections(pool, 300)

	// no spare: b keeps its slot while dead and its keys go to a and c
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(monitoring.TimeoutDelay), "c": his(100)})
	require.Equal(t, []string{"a", "b", "c"}, pool.Slots(N.NetworkTCP))
	during := hSelections(pool, 300)
	moved := map[string]int{}
	for domain, member := range before {
		if member == "b" {
			require.NotEqual(t, "b", during[domain])
			moved[during[domain]]++
		} else {
			require.Equal(t, member, during[domain], "the keys of working slots do not move")
		}
	}
	require.NotZero(t, moved["a"], "b's keys spread over a")
	require.NotZero(t, moved["c"], "and c")

	// b answers again: its keys come back
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(100), "c": his(100)})
	require.Equal(t, before, hSelections(pool, 300))
}

func TestH_PoolTolerance(t *testing.T) {
	pool := hPool(t, option.BalancerOutboundOptions{Pool: 1, PoolTolerance: 100}, "a", "b")
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(300), "b": his(250)})
	require.Equal(t, []string{"a"}, pool.Slots(N.NetworkTCP), "b is faster, but not by more than 100 ms")
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(300), "b": his(150)})
	require.Equal(t, []string{"b"}, pool.Slots(N.NetworkTCP), "b is faster by more than 100 ms")
}

func TestH_PoolStickyHashNoneRotates(t *testing.T) {
	pool := hPool(t, option.BalancerOutboundOptions{Pool: 2, StickyHash: []string{"none"}}, "a", "b", "c")
	pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(100), "c": his(100)})
	var got []string
	for range 4 {
		got = append(got, pool.Select(hDomain("same.example"), N.NetworkTCP, true).Tag())
	}
	require.Equal(t, []string{"a", "b", "a", "b"}, got)
}

func TestH_PoolStickyHashFields(t *testing.T) {
	pool := hPool(t, option.BalancerOutboundOptions{Pool: 8, StickyHash: []string{"dest_port"}}, "a", "b", "c", "d", "e", "f", "g", "h")
	history := map[string]*adapter.URLTestHistory{}
	for _, tag := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		history[tag] = his(100)
	}
	pool.UpdateOutboundsInfo(history)
	first := pool.Select(adapter.InboundContext{Destination: M.ParseSocksaddr("1.1.1.1:443")}, N.NetworkTCP, true)
	for _, destination := range []string{"8.8.8.8:443", "9.9.9.9:443", "example.com:443"} {
		require.Equal(t, first, pool.Select(adapter.InboundContext{Destination: M.ParseSocksaddr(destination)}, N.NetworkTCP, true), "only the port counts")
	}
}

func TestH_PoolOptions(t *testing.T) {
	for _, options := range []option.BalancerOutboundOptions{
		{Pool: -1},
		{PoolTolerance: 15001},
		{StickyHash: []string{"none", "domain"}},
		{StickyHash: []string{"user"}},
	} {
		_, err := NewPool(outs(newFake("a")), options)
		require.Error(t, err, "%+v", options)
	}
	pool, err := NewPool(outs(newFake("a")), option.BalancerOutboundOptions{})
	require.NoError(t, err)
	require.Equal(t, defaultPoolSize, pool.size)
	require.Equal(t, defaultStickyHash, pool.stickyHash)
	require.Len(t, pool.Slots(N.NetworkTCP), 1, "min(pool, members)")
}

func TestH_PoolDoesNotInterrupt(t *testing.T) {
	pool := hPool(t, option.BalancerOutboundOptions{Pool: 2}, "a", "b", "c")
	require.False(t, pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(100), "c": his(100)}))
	require.False(t, pool.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(monitoring.TimeoutDelay), "b": his(100), "c": his(100)}))
}
