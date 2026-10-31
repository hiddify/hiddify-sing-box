package balancer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func timeout() *adapter.URLTestHistory { return his(monitoring.TimeoutDelay) }

func cached(delay uint16) *adapter.URLTestHistory {
	return &adapter.URLTestHistory{Delay: delay, Time: time.Now(), IsFromCache: true}
}

// The lowest-delay strategy keeps its member until it dies or another one is faster by more
// than the tolerance (50 ms when unset): the jitter between two close servers moved the
// selection, and every move closed every connection.
func TestH_BalancerLowestDelayTolerance(t *testing.T) {
	s := NewLowestDelay(outs(newFake("a"), newFake("b"), newFake("c")), option.BalancerOutboundOptions{})
	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(120), "c": timeout()}), "the first member stays")
	require.Equal(t, "a", s.Now())

	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(60), "c": timeout()}), "40 ms faster is within the tolerance")
	require.Equal(t, "a", s.Now())
	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(50), "c": timeout()}), "exactly the tolerance is not enough")
	require.Equal(t, "a", s.Now())

	require.True(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": his(49), "c": timeout()}))
	require.Equal(t, "b", s.Now())

	require.True(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(100), "b": timeout(), "c": his(90)}), "a dead member is left at once")
	require.Equal(t, "c", s.Now())

	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": timeout(), "b": timeout(), "c": timeout()}), "with every member dead, nothing moves")
	require.Equal(t, "c", s.Now())

	// a fresh result beats a cached one of the same member, since the cache adds 20 s
	s = NewLowestDelay(outs(newFake("a"), newFake("b")), option.BalancerOutboundOptions{Tolerance: 100})
	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": cached(40), "b": cached(300)}))
	require.Equal(t, "a", s.Now())
	require.True(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": cached(40), "b": his(300)}), "the first fresh result wins over the cache")
	require.Equal(t, "b", s.Now())
	require.True(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(40), "b": his(300)}))
	require.Equal(t, "a", s.Now())
	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(40), "b": his(30)}), "tolerance is the option's")
	require.Equal(t, "a", s.Now())
}

// The relative tolerance: a member must also be faster by more than tolerance_ratio of the
// selected member's delay (a tenth when unset), so a slow server is not left for a few
// milliseconds of jitter.
func TestH_BalancerLowestDelayToleranceRatio(t *testing.T) {
	require.Equal(t, uint32(50), switchThreshold(100, 50, 0.1), "the fixed tolerance when it is larger")
	require.Equal(t, uint32(100), switchThreshold(1000, 50, 0.1), "the share when it is larger")
	require.Equal(t, uint32(300), switchThreshold(1000, 50, 0.3))

	s := NewLowestDelay(outs(newFake("a"), newFake("b")), option.BalancerOutboundOptions{Tolerance: 50})
	s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(1000), "b": his(2000)})
	require.Equal(t, "a", s.Now())
	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(1000), "b": his(920)}), "80 ms is more than the tolerance but less than a tenth")
	require.Equal(t, "a", s.Now())
	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(1000), "b": his(900)}), "exactly a tenth is not enough")
	require.True(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(1000), "b": his(899)}))
	require.Equal(t, "b", s.Now())

	s = NewLowestDelay(outs(newFake("a"), newFake("b")), option.BalancerOutboundOptions{Tolerance: 50, ToleranceRatio: 0.3})
	s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(1000), "b": his(2000)})
	require.False(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(1000), "b": his(750)}), "the option's share")
	require.True(t, s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(1000), "b": his(699)}))
}

type fakeCache struct {
	adapter.CacheFile
	access sync.Mutex
	data   map[string]*adapter.SavedBinary
}

func (c *fakeCache) LoadBinary(tag string) *adapter.SavedBinary {
	c.access.Lock()
	defer c.access.Unlock()
	return c.data[tag]
}

func (c *fakeCache) SaveBinary(tag string, set *adapter.SavedBinary) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.data[tag] = set
	return nil
}

// At start the balancer selects from the cached results, so the first connections, and the
// first test, go to the member that was fastest last time, not to the first in the list.
func TestH_BalancerStartsFromCache(t *testing.T) {
	cache := &fakeCache{data: map[string]*adapter.SavedBinary{
		"outbound_monitoring_history": {Content: []byte(`{"outbound_data":{"a":{"delay":300,"time":"2026-01-01T00:00:00Z"},"b":{"delay":40,"time":"2026-01-01T00:00:00Z"}}}`)},
	}}
	a, b := newFake("a"), newFake("b")
	ctx, manager := newBalancerCtx(t, a, b)
	ctx = service.ContextWith[adapter.CacheFile](ctx, cache)
	logger := log.NewNOPFactory().NewLogger("test")
	monitor, err := monitoring.NewOutboundMonitoring(ctx, logger, option.MonitoringOptions{URLs: []string{"http://127.0.0.1:1/generate_204"}})
	require.NoError(t, err)
	service.MustRegisterPtr(ctx, monitor)
	defer monitor.Close()

	out, err := NewLoadBalance(ctx, nil, logger, "lb", option.BalancerOutboundOptions{Outbounds: []string{"a", "b"}, Strategy: StrategyLowestDelay})
	require.NoError(t, err)
	lb := out.(*Balancer)
	manager.list = append(manager.list, lb)
	require.NoError(t, htest.Start(monitor, adapter.StartStateInitialize))
	require.NoError(t, lb.Start())
	require.Equal(t, "b", lb.Now())
}

type stableFixture struct {
	lb   *Balancer
	a, b *fakeOutbound
	ctx  context.Context
}

func newStable(t *testing.T, options option.BalancerOutboundOptions) *stableFixture {
	a, b := newFake("a"), newFake("b")
	ctx, _ := newBalancerCtx(t, a, b)
	options.Outbounds = []string{"a", "b"}
	out, err := NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("balancer"), "lb", options)
	require.NoError(t, err)
	lb := out.(*Balancer)
	require.NoError(t, lb.Start())
	return &stableFixture{lb: lb, a: a, b: b, ctx: ctx}
}

// dial opens a connection that came in from an inbound, the kind interrupt_exist_connections closes.
func (f *stableFixture) dial(t *testing.T) net.Conn {
	ctx := interrupt.ContextWithIsExternalConnection(adapter.WithContext(f.ctx, &adapter.InboundContext{}), true)
	conn, err := f.lb.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("example.com", 80))
	require.NoError(t, err)
	return conn
}

func closed(conn net.Conn) bool {
	conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := conn.Write([]byte{1})
	return err != nil && !isTimeout(err)
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func requireOpen(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	time.Sleep(20 * time.Millisecond)
	require.False(t, closed(conn), msg)
}

func requireClosed(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	require.Eventually(t, func() bool { return closed(conn) }, time.Second, 10*time.Millisecond, msg)
}

// Moving to a faster member does not close the connections on the old one; only the connections
// of a member that died are closed, and only those: a voice call through a working server is
// not cut because another server got faster.
func TestH_BalancerInterruptsOnlyDeadMember(t *testing.T) {
	f := newStable(t, option.BalancerOutboundOptions{Strategy: StrategyLowestDelay, InterruptExistConnections: true})
	f.lb.settled.Store(true)
	f.lb.update(map[string]*adapter.URLTestHistory{"a": his(30), "b": his(100)})
	require.Equal(t, "a", f.lb.Now())
	onA := f.dial(t)

	f.lb.update(map[string]*adapter.URLTestHistory{"a": his(300), "b": his(100)})
	require.Equal(t, "b", f.lb.Now())
	requireOpen(t, onA, "a faster member must not close the connections of the old one")
	onB := f.dial(t)
	require.Equal(t, int32(1), f.b.dialed.Load())

	f.lb.update(map[string]*adapter.URLTestHistory{"a": timeout(), "b": his(100)})
	requireClosed(t, onA, "the connections of a dead member are closed")
	requireOpen(t, onB, "the connections of the other members stay")

	f.lb.update(map[string]*adapter.URLTestHistory{"a": his(20), "b": timeout()})
	require.Equal(t, "a", f.lb.Now())
	requireClosed(t, onB, "the selected member dying moves the group and closes its connections")

	// without interrupt_exist_connections, the inbound connections of a dead member stay
	f = newStable(t, option.BalancerOutboundOptions{Strategy: StrategyLowestDelay})
	f.lb.settled.Store(true)
	f.lb.update(map[string]*adapter.URLTestHistory{"a": his(30), "b": his(100)})
	onA = f.dial(t)
	f.lb.update(map[string]*adapter.URLTestHistory{"a": timeout(), "b": his(100)})
	requireOpen(t, onA, "external connections are kept without interrupt_exist_connections")
}

// The first tests after start may move the selection several times; the connections made
// before them are moved once, when the settle window ends, and never again for speed.
func TestH_BalancerSettlesOnce(t *testing.T) {
	f := newStable(t, option.BalancerOutboundOptions{Strategy: StrategyLowestDelay, InterruptExistConnections: true})
	require.Equal(t, "a", f.lb.Now())
	early := f.dial(t)

	f.lb.update(map[string]*adapter.URLTestHistory{"a": his(200), "b": his(20)})
	require.Equal(t, "b", f.lb.Now())
	requireOpen(t, early, "no interrupt before the settle window ends")
	onB := f.dial(t)

	f.lb.settle(map[string]*adapter.URLTestHistory{"a": his(200), "b": his(20)})
	requireClosed(t, early, "the settle moves the connections of the members that are not selected")
	requireOpen(t, onB, "the connections of the selected member stay")
	require.True(t, f.lb.settled.Load())

	f.lb.update(map[string]*adapter.URLTestHistory{"a": his(10), "b": his(200)})
	require.Equal(t, "a", f.lb.Now())
	requireOpen(t, onB, "after the settle, a faster member never closes connections")

	// nothing is closed when no member has a fresh result yet
	f = newStable(t, option.BalancerOutboundOptions{Strategy: StrategyRoundRobin, InterruptExistConnections: true})
	early = f.dial(t)
	f.lb.settle(map[string]*adapter.URLTestHistory{"a": cached(100), "b": cached(5000)})
	requireOpen(t, early, "no result of this run, nothing to settle on")
	require.False(t, f.lb.settled.Load())
	slow := map[string]*adapter.URLTestHistory{"a": his(100), "b": his(5000)}
	f.lb.update(slow)
	f.lb.settle(slow)
	require.True(t, f.lb.settled.Load())
	requireClosed(t, early, "a member outside the acceptable delay is left at the settle")
}
