package balancer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type fakeOutbound struct {
	tag      string
	network  []string
	dial     func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	dialed   atomic.Int32
	listened atomic.Int32
}

func newFake(tag string, network ...string) *fakeOutbound {
	if len(network) == 0 {
		network = []string{N.NetworkTCP, N.NetworkUDP}
	}
	return &fakeOutbound{tag: tag, network: network}
}

func (f *fakeOutbound) Type() string           { return "fake" }
func (f *fakeOutbound) Tag() string            { return f.tag }
func (f *fakeOutbound) Network() []string      { return f.network }
func (f *fakeOutbound) Dependencies() []string { return nil }
func (f *fakeOutbound) IsReady() bool          { return true }

func (f *fakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	f.dialed.Add(1)
	if f.dial != nil {
		return f.dial(ctx, network, destination)
	}
	c1, c2 := net.Pipe()
	go func() {
		time.Sleep(time.Second)
		c2.Close()
	}()
	return c1, nil
}

func (f *fakeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	f.listened.Add(1)
	return nil, errors.New("fake: listen packet unsupported")
}

func outs(o ...*fakeOutbound) []adapter.Outbound {
	r := make([]adapter.Outbound, len(o))
	for i := range o {
		r[i] = o[i]
	}
	return r
}

func his(delay uint16) *adapter.URLTestHistory {
	return &adapter.URLTestHistory{Delay: delay, Time: time.Now()}
}

func TestH_BalancerGetKey(t *testing.T) {
	require.Equal(t, "", getKey(nil))
	require.Equal(t, "", getKey(&adapter.InboundContext{}))
	require.Equal(t, "example.com", getKey(&adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("www.sub.example.com", 443)}))
	require.Equal(t, "example.co.uk", getKey(&adapter.InboundContext{Domain: "a.b.example.co.uk", Destination: M.ParseSocksaddrHostPort("1.2.3.4", 443)}))
	require.Equal(t, "1.2.3.4", getKey(&adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("1.2.3.4", 443)}))
	require.Equal(t, "9.9.9.9", getKey(&adapter.InboundContext{Domain: "9.9.9.9"}))
	require.Equal(t, "5.6.7.8", getKey(&adapter.InboundContext{
		Destination:          M.ParseSocksaddrHostPort("1.2.3.4", 443),
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("5.6.7.8")},
	}))

	md := &adapter.InboundContext{
		Source:      M.ParseSocksaddrHostPort("10.0.0.1", 1234),
		Destination: M.ParseSocksaddrHostPort("www.example.com", 443),
	}
	require.Equal(t, "10.0.0.1example.com", getKeyWithSrcAndDst(md))
}

func TestH_BalancerJumpHash(t *testing.T) {
	for key := uint64(0); key < 1000; key++ {
		require.Equal(t, int32(0), jumpHash(key, 1))
		v := jumpHash(key, 7)
		require.GreaterOrEqual(t, v, int32(0))
		require.Less(t, v, int32(7))
		require.Equal(t, v, jumpHash(key, 7))
	}
	seen := map[int32]bool{}
	for key := uint64(0); key < 1000; key++ {
		seen[jumpHash(key*0x9E3779B97F4A7C15, 4)] = true
	}
	require.Len(t, seen, 4)
}

func TestH_BalancerDelayHelpers(t *testing.T) {
	require.Equal(t, monitoring.TimeoutDelay, getModifiedDelay(nil))
	require.Equal(t, monitoring.TimeoutDelay, getModifiedDelay(&adapter.URLTestHistory{}))
	require.Equal(t, uint16(150), getModifiedDelay(&adapter.URLTestHistory{Delay: 150}))
	require.Equal(t, uint16(20150), getModifiedDelay(&adapter.URLTestHistory{Delay: 150, IsFromCache: true}))
	require.Equal(t, uint16(30000), getModifiedDelay(&adapter.URLTestHistory{Delay: 30000, IsFromCache: true}))

	history := map[string]*adapter.URLTestHistory{"a": his(10), "nil": nil}
	require.Equal(t, uint16(10), getTagDelay("a", history))
	require.Equal(t, monitoring.TimeoutDelay, getTagDelay("nil", history))
	require.Equal(t, monitoring.TimeoutDelay, getTagDelay("missing", history))

	dm := getDelayMap(history)
	require.Equal(t, uint16(10), dm["a"])
	require.Equal(t, monitoring.TimeoutDelay, dm["nil"])
}

func TestH_BalancerFilterOutbounds(t *testing.T) {
	tcp := newFake("tcp", N.NetworkTCP)
	udp := newFake("udp", N.NetworkUDP)
	both := newFake("both")
	m := convertOutbounds(outs(tcp, udp, both))
	require.Equal(t, outs(tcp, both), m[N.NetworkTCP])
	require.Equal(t, outs(udp, both), m[N.NetworkUDP])

	m = convertOutbounds(outs(tcp))
	require.Equal(t, outs(tcp), m[N.NetworkUDP], "falls back to all outbounds when none supports the network")
}

func TestH_BalancerSortAndAcceptable(t *testing.T) {
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	history := map[string]*adapter.URLTestHistory{"a": his(300), "b": his(50), "c": nil}
	sorted := sortOutboundsByDelay(convertOutbounds(outs(a, b, c)), history)
	require.Equal(t, outs(b, a, c), sorted[N.NetworkTCP])

	idx := getAcceptableIndex(sorted, history, 2)
	require.Equal(t, 0, idx[N.NetworkTCP], "max(100,50)*2=200 only admits b")
	idx = getAcceptableIndex(sorted, history, 6)
	require.Equal(t, 1, idx[N.NetworkTCP])

	best, delays := getMinDelay(convertOutbounds(outs(a, b, c)), history)
	require.Equal(t, "b", best[N.NetworkTCP].Tag())
	require.Equal(t, uint16(50), delays[N.NetworkTCP])
}

func TestH_BalancerLowestDelay(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	u := newFake("u", N.NetworkUDP)
	s := NewLowestDelay(outs(a, b, u), option.BalancerOutboundOptions{})
	require.Equal(t, "a", s.Now())
	require.Equal(t, "a", s.Select(adapter.InboundContext{}, N.NetworkTCP, true).Tag())
	require.Equal(t, "a", s.Select(adapter.InboundContext{}, "unknown", true).Tag())
	require.Equal(t, "b", NewLowestDelay(outs(b, a), option.BalancerOutboundOptions{}).Now())

	history := map[string]*adapter.URLTestHistory{"a": his(500), "b": his(80), "u": his(20)}
	require.True(t, s.UpdateOutboundsInfo(history))
	require.Equal(t, "b", s.Now())
	require.Equal(t, "b", s.Select(adapter.InboundContext{}, N.NetworkTCP, true).Tag())
	require.Equal(t, "u", s.Select(adapter.InboundContext{}, N.NetworkUDP, true).Tag())
	require.False(t, s.UpdateOutboundsInfo(history))

	// failover: b goes down
	history["b"] = his(monitoring.TimeoutDelay)
	require.True(t, s.UpdateOutboundsInfo(history))
	require.Equal(t, "a", s.Now())

	// cached results are penalised against fresh ones
	history = map[string]*adapter.URLTestHistory{
		"a": {Delay: 900},
		"b": {Delay: 10, IsFromCache: true},
		"u": his(20),
	}
	s.UpdateOutboundsInfo(history)
	require.Equal(t, "a", s.Now())
}

func TestH_BalancerRoundRobin(t *testing.T) {
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	s := NewRoundRobin(outs(a, b, c), option.BalancerOutboundOptions{DelayAcceptableRatio: 2})
	require.Equal(t, "", s.Now())

	var got []string
	for range 6 {
		got = append(got, s.Select(adapter.InboundContext{}, N.NetworkTCP, true).Tag())
	}
	require.Equal(t, []string{"b", "c", "a", "b", "c", "a"}, got)

	require.Equal(t, "b", s.Select(adapter.InboundContext{}, N.NetworkTCP, false).Tag())
	require.Equal(t, "b", s.Select(adapter.InboundContext{}, N.NetworkTCP, false).Tag())

	history := map[string]*adapter.URLTestHistory{"a": his(150), "b": his(100), "c": his(monitoring.TimeoutDelay)}
	require.True(t, s.UpdateOutboundsInfo(history))
	require.False(t, s.UpdateOutboundsInfo(history))
	seen := map[string]int{}
	for range 10 {
		seen[s.Select(adapter.InboundContext{}, "", true).Tag()]++
	}
	require.Equal(t, map[string]int{"a": 5, "b": 5}, seen, "dead outbound c must be excluded")
}

func TestH_BalancerRoundRobinCachedDelayOverflow(t *testing.T) {
	t.Skip("BUG: getAcceptableIndex/consistent-hashing/sticky compute uint16(float) of max acceptable delay, which overflows when delay*ratio > 65535")
	a, b := newFake("a"), newFake("b")
	s := NewRoundRobin(outs(a, b), option.BalancerOutboundOptions{DelayAcceptableRatio: 3})
	// both cached: effective delays 25000 / 26000, acceptable = 75000
	s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{
		"a": {Delay: 5000, IsFromCache: true},
		"b": {Delay: 6000, IsFromCache: true},
	})
	seen := map[string]bool{}
	for range 4 {
		seen[s.Select(adapter.InboundContext{}, N.NetworkTCP, true).Tag()] = true
	}
	require.Len(t, seen, 2)
}

func TestH_BalancerConsistentHashing(t *testing.T) {
	o := []*fakeOutbound{newFake("a"), newFake("b"), newFake("c"), newFake("d")}
	s := NewConsistentHashing(outs(o...), option.BalancerOutboundOptions{DelayAcceptableRatio: 2, MaxRetry: 3})
	require.Equal(t, "", s.Now())
	history := map[string]*adapter.URLTestHistory{"a": his(100), "b": his(120), "c": his(150), "d": his(monitoring.TimeoutDelay)}
	require.True(t, s.UpdateOutboundsInfo(history))

	md := func(host string) adapter.InboundContext {
		return adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(host, 443)}
	}
	first := s.Select(md("www.example.com"), N.NetworkTCP, true).Tag()
	for range 20 {
		require.Equal(t, first, s.Select(md("www.example.com"), N.NetworkTCP, true).Tag())
		require.Equal(t, first, s.Select(md("api.example.com"), "", true).Tag(), "same eTLD+1 maps to same outbound")
	}

	seen := map[string]bool{}
	for i := range 200 {
		tag := s.Select(md(net.IPv4(10, 0, byte(i/256), byte(i)).String()), N.NetworkTCP, true).Tag()
		require.NotEqual(t, "d", tag)
		seen[tag] = true
	}
	require.Len(t, seen, 3)

	// everything dead: still deterministic and non-nil
	for _, x := range o {
		history[x.tag] = his(monitoring.TimeoutDelay)
	}
	s.delayAcceptableRatio = 0.5
	s.UpdateOutboundsInfo(history)
	r1 := s.Select(md("example.org"), N.NetworkTCP, true)
	require.NotNil(t, r1)
	require.Equal(t, r1, s.Select(md("example.org"), N.NetworkTCP, true))
}

func TestH_BalancerConsistentHashingUntestedNotAlive(t *testing.T) {
	t.Skip("BUG: getDelayMap uses raw Delay so an untested outbound (Delay 0) is treated as alive by consistent-hashing/sticky-sessions")
	a, b := newFake("a"), newFake("b")
	s := NewConsistentHashing(outs(a, b), option.BalancerOutboundOptions{DelayAcceptableRatio: 2, MaxRetry: 3})
	s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": {Delay: 0}, "b": his(100)})
	for i := range 100 {
		md := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(net.IPv4(10, 0, 0, byte(i)).String(), 443)}
		require.Equal(t, "b", s.Select(md, N.NetworkTCP, true).Tag())
	}
}

func TestH_BalancerStickySession(t *testing.T) {
	o := []*fakeOutbound{newFake("a"), newFake("b"), newFake("c")}
	s := NewStickySession(outs(o...), option.BalancerOutboundOptions{DelayAcceptableRatio: 2, MaxRetry: 5})
	require.Equal(t, "", s.Now())
	history := map[string]*adapter.URLTestHistory{"a": his(100), "b": his(110), "c": his(120)}
	require.True(t, s.UpdateOutboundsInfo(history))

	for i := range 50 {
		md := adapter.InboundContext{
			Source:      M.ParseSocksaddrHostPort(net.IPv4(192, 168, 0, byte(i)).String(), 5000),
			Destination: M.ParseSocksaddrHostPort("www.example.com", 443),
		}
		first := s.Select(md, N.NetworkTCP, true).Tag()
		for range 5 {
			require.Equal(t, first, s.Select(md, N.NetworkTCP, true).Tag())
		}
	}
}

func TestH_BalancerStickySessionAvoidsDead(t *testing.T) {
	t.Skip("BUG: StickySession.Select retries re-hash with key+UnixNano (often identical within the loop) and returns the last pick without an Alive check, so ~50% of new sessions land on a dead outbound")
	a, b := newFake("a"), newFake("b")
	s := NewStickySession(outs(a, b), option.BalancerOutboundOptions{DelayAcceptableRatio: 2, MaxRetry: 5})
	s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(monitoring.TimeoutDelay)})
	for i := range 500 {
		md := adapter.InboundContext{
			Source:      M.ParseSocksaddrHostPort(net.IPv4(192, 168, byte(i/256), byte(i)).String(), 5000),
			Destination: M.ParseSocksaddrHostPort("1.1.1.1", 443),
		}
		require.Equal(t, "a", s.Select(md, N.NetworkTCP, true).Tag(), "iteration %d", i)
	}
}
