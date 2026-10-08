package monitoring

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/ipinfo"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

type fakeOutbound struct {
	tag  string
	deps []string
	dial func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func (f *fakeOutbound) Type() string           { return "fake" }
func (f *fakeOutbound) Tag() string            { return f.tag }
func (f *fakeOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (f *fakeOutbound) Dependencies() []string { return f.deps }
func (f *fakeOutbound) IsReady() bool          { return true }
func (f *fakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if f.dial != nil {
		return f.dial(ctx, network, destination)
	}
	return nil, errors.New("fake: unreachable")
}
func (f *fakeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("fake: unsupported")
}

type fakeGroup struct {
	fakeOutbound
	all      []string
	selected adapter.Outbound
}

func (g *fakeGroup) All() []string                                     { return g.all }
func (g *fakeGroup) Selected(network string) adapter.Outbound          { return g.selected }
func (g *fakeGroup) AttachConnection(closer io.Closer) (detach func()) { return func() {} }

type fakeOutboundManager struct {
	adapter.OutboundManager
	list []adapter.Outbound
}

func (m *fakeOutboundManager) Outbounds() []adapter.Outbound { return m.list }
func (m *fakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, o := range m.list {
		if o.Tag() == tag {
			return o, true
		}
	}
	return nil, false
}

type fakeEndpointManager struct {
	adapter.EndpointManager
}

func (m *fakeEndpointManager) Endpoints() []adapter.Endpoint { return nil }

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

func newTestMonitor(t *testing.T, cache adapter.CacheFile, options option.MonitoringOptions, outbounds ...adapter.Outbound) *OutboundMonitoring {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &fakeOutboundManager{list: outbounds})
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &fakeEndpointManager{})
	if cache != nil {
		ctx = service.ContextWith[adapter.CacheFile](ctx, cache)
	}
	m, err := NewOutboundMonitoring(ctx, log.NewNOPFactory().NewLogger("monitoring"), options)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func setHistory(m *OutboundMonitoring, tag string, delay uint16, fromCache bool, info *ipinfo.IpInfo) {
	s := m.reg().outbounds[tag]
	s.mu.Lock()
	s.history = adapter.URLTestHistory{Delay: delay, Time: time.Now(), IpInfo: info}
	s.from_cache = fromCache
	s.mu.Unlock()
}

func TestH_MonitoringBroadcaster(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := NewBroadcaster[int](ctx)
	s1 := b.Subscribe(1)
	s2 := b.Subscribe(0)
	b.Publish(1)
	require.Equal(t, 1, <-s1)
	select {
	case <-s2:
		t.Fatal("unbuffered slow subscriber should drop events")
	default:
	}
	b.Publish(2)
	b.Publish(3)
	require.Equal(t, 2, <-s1)

	b.Unsubscribe(s2)
	_, ok := <-s2
	require.False(t, ok)
	b.Unsubscribe(s2)

	cancel()
	require.Eventually(t, func() bool {
		select {
		case _, ok := <-s1:
			return !ok
		default:
			return false
		}
	}, time.Second, time.Millisecond)
	_, ok = <-b.Subscribe(1)
	require.False(t, ok, "subscribe after close yields a closed channel")
	b.Publish(4)
	b.Close()
	b.Close()
}

func TestH_MonitoringMergeIpInfo(t *testing.T) {
	old := &ipinfo.IpInfo{IP: "1.1.1.1", CountryCode: "DE", Org: "Old"}
	newer := &ipinfo.IpInfo{IP: "2.2.2.2"}
	require.Nil(t, mergeIpInfo(nil, nil))
	require.Equal(t, newer, mergeIpInfo(nil, newer))
	require.Equal(t, old, mergeIpInfo(old, nil))
	merged := mergeIpInfo(old, newer)
	require.Equal(t, &ipinfo.IpInfo{IP: "2.2.2.2", CountryCode: "DE", Org: "Old"}, merged)
	require.Equal(t, "", newer.CountryCode, "input must not be mutated")
	merged = mergeIpInfo(old, &ipinfo.IpInfo{IP: "3.3.3.3", CountryCode: "US", Org: "New"})
	require.Equal(t, "US", merged.CountryCode)
	require.Equal(t, "New", merged.Org)
}

func TestH_MonitoringRealTag(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	g := &fakeGroup{fakeOutbound: fakeOutbound{tag: "g"}, all: []string{"a"}}
	require.Equal(t, "a", RealTag(a))
	require.Equal(t, "g", RealTag(g))
	g.selected = a
	require.Equal(t, "a", RealTag(g))
}

func TestH_MonitoringGroupsAndHistory(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	b := &fakeOutbound{tag: "b"}
	c := &fakeOutbound{tag: "c", deps: []string{"a"}}
	urltestGroup := &fakeGroup{fakeOutbound: fakeOutbound{tag: "auto"}, all: []string{"a", "b"}}
	selector := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, all: []string{"auto", "c"}, selected: c}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, a, b, c, urltestGroup, selector)
	require.Equal(t, "outbound-monitoring", m.Name())
	require.NoError(t, m.Start(adapter.StartStateInitialize))

	require.Len(t, m.reg().groups, 3)
	require.Len(t, m.reg().groups[""].outbounds, 5)
	require.ElementsMatch(t, []string{"", "auto"}, m.reg().outbounds["a"].groupTags)
	require.Equal(t, []string{"c"}, m.reg().outbounds["a"].dependenciesInverse)

	_, err := m.SubscribeGroup("missing")
	require.Error(t, err)
	require.Error(t, m.UnsubscribeGroup("missing", nil))
	require.Error(t, m.InvalidateTest("missing"))
	require.Error(t, m.SignalChange("missing"))
	require.Empty(t, m.OutboundsHistory("missing"))
	require.Nil(t, m.getUrlTest("missing"))

	setHistory(m, "a", 300, false, &ipinfo.IpInfo{IP: "1.1.1.1"})
	setHistory(m, "b", 120, false, nil)
	setHistory(m, "c", 50, true, nil)

	h := m.OutboundsHistory("auto")
	require.Len(t, h, 2)
	require.Equal(t, uint16(300), h["a"].Delay)
	require.Equal(t, "1.1.1.1", h["a"].IpInfo.IP)
	require.False(t, h["a"].IsFromCache)

	groupHis := m.getUrlTest("auto")
	require.Equal(t, uint16(120), groupHis.Delay, "group history is the best fresh delay")
	require.False(t, groupHis.IsFromCache)

	h = m.OutboundsHistory("select")
	require.Equal(t, uint16(50), h["c"].Delay)
	require.True(t, h["c"].IsFromCache)
	require.Equal(t, uint16(120), h["auto"].Delay)
	require.Equal(t, uint16(50), m.getUrlTest("select").Delay, "selector follows its selected outbound")

	// all fresh results timed out -> fall back to cached
	setHistory(m, "a", TimeoutDelay, false, nil)
	setHistory(m, "b", 70, true, &ipinfo.IpInfo{IP: "7.7.7.7"})
	groupHis = m.getUrlTest("auto")
	require.Equal(t, uint16(70), groupHis.Delay)
	require.True(t, groupHis.IsFromCache)

	setHistory(m, "a", 0, false, nil)
	setHistory(m, "b", 0, false, nil)
	require.Nil(t, m.getUrlTest("auto"), "untested outbounds yield no group history")
}

func TestH_MonitoringQueueAndApplyResult(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	b := &fakeOutbound{tag: "b"}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"a", "b"}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, a, b, grp)
	require.NoError(t, m.Start(adapter.StartStateInitialize))

	targets := m.collectCycleTargets()
	require.ElementsMatch(t, []string{"a", "b"}, targets, "groups are never tested directly")

	require.True(t, m.enqueueTask(&testTask{outboundTag: "a", cycleID: 1}))
	require.False(t, m.enqueueTask(&testTask{outboundTag: "a", cycleID: 1}), "same cycle is deduplicated")
	require.True(t, m.enqueueTask(&testTask{outboundTag: "a", priority: true}))
	require.False(t, m.enqueueTask(&testTask{outboundTag: "a", priority: true}))
	require.False(t, m.enqueueTask(&testTask{outboundTag: "unknown"}))
	require.Equal(t, []string{"b"}, m.collectCycleTargets(), "queued outbounds are skipped")

	stored := m.applyResult(testOutcome{outboundTag: "a", history: adapter.URLTestHistory{Delay: 42, Time: time.Now(), IpInfo: &ipinfo.IpInfo{IP: "4.4.4.4"}}})
	require.Equal(t, uint16(42), stored.Delay)
	require.True(t, m.cacheDirty.Load())
	state := m.reg().outbounds["a"]
	require.False(t, state.queued)
	require.False(t, state.priorityQueued)
	require.False(t, state.invalid)
	require.Equal(t, uint16(42), m.history.LoadURLTestHistory("a").Delay)

	m.applyResult(testOutcome{outboundTag: "a", history: adapter.URLTestHistory{Delay: TimeoutDelay, Time: time.Now()}, err: errors.New("x")})
	require.True(t, state.invalid)
	require.Equal(t, "4.4.4.4", state.history.IpInfo.IP, "ip info survives a failed test")
	require.Len(t, m.reg().groups["grp"].notifyCh, 1)

	require.NoError(t, m.InvalidateTest("b"))
	require.True(t, m.reg().outbounds["b"].invalid)
	require.True(t, m.reg().outbounds["b"].priorityQueued)

	require.Contains(t, m.collectCycleTargets(), "a")
}

func TestH_MonitoringSaveLoadHistory(t *testing.T) {
	cache := &fakeCache{data: map[string]*adapter.SavedBinary{}}
	a := &fakeOutbound{tag: "a"}
	b := &fakeOutbound{tag: "b"}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"a", "b"}}
	m := newTestMonitor(t, cache, option.MonitoringOptions{}, a, b, grp)
	require.NoError(t, m.Start(adapter.StartStateInitialize))
	setHistory(m, "a", 77, false, &ipinfo.IpInfo{IP: "8.8.8.8", CountryCode: "US"})
	setHistory(m, "b", TimeoutDelay, false, nil)
	require.NoError(t, m.saveHistory())
	require.NotNil(t, cache.LoadBinary("outbound_monitoring_history"))

	m2 := newTestMonitor(t, cache, option.MonitoringOptions{}, a, b, grp)
	require.NoError(t, m2.Start(adapter.StartStateInitialize))
	ha := m2.getUrlTest("a")
	require.Equal(t, uint16(77), ha.Delay)
	require.True(t, ha.IsFromCache)
	require.Equal(t, "US", ha.IpInfo.CountryCode)
	require.Equal(t, uint16(0), m2.getUrlTest("b").Delay, "cached timeouts are reset to untested")

	cache.data["outbound_monitoring_history"] = &adapter.SavedBinary{Content: []byte("{garbage")}
	m3 := newTestMonitor(t, cache, option.MonitoringOptions{}, a, b, grp)
	require.NoError(t, m3.Start(adapter.StartStateInitialize))
	require.Equal(t, uint16(0), m3.getUrlTest("a").Delay)
}

func TestH_MonitoringStartRejectsUnknownGroupMember(t *testing.T) {
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"ghost"}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, grp)
	require.Error(t, m.Start(adapter.StartStateInitialize))
}

func TestH_MonitoringCycleEndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddr := M.ParseSocksaddr(server.Listener.Addr().String())
	var dialer net.Dialer
	good := &fakeOutbound{tag: "good", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination != serverAddr {
			return nil, errors.New("unreachable")
		}
		return dialer.DialContext(ctx, network, destination.String())
	}}
	bad := &fakeOutbound{tag: "bad"}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"good", "bad"}}
	cache := &fakeCache{data: map[string]*adapter.SavedBinary{}}

	m := newTestMonitor(t, cache, option.MonitoringOptions{
		URLs:           []string{"http://127.0.0.1:1/unreachable", server.URL + "/generate_204"},
		Workers:        2,
		DebounceWindow: badoption.Duration(10 * time.Millisecond),
		URLTestTimeout: badoption.Duration(2 * time.Second),
	}, good, bad, grp)
	require.NoError(t, m.Start(adapter.StartStateInitialize))
	events, err := m.SubscribeGroup("grp")
	require.NoError(t, err)
	require.NoError(t, m.Start(adapter.StartStatePostStart))

	select {
	case <-events:
	case <-time.After(4 * time.Second):
		t.Fatal("no group event")
	}
	require.Eventually(t, func() bool {
		h := m.OutboundsHistory("grp")
		return h["good"].Delay > 0 && h["good"].Delay < TimeoutDelay && h["bad"].Delay == TimeoutDelay
	}, 4*time.Second, 10*time.Millisecond)
	require.Equal(t, uint32(1), m.currentLinkIndex.Load(), "switches to the next URL when every test of a stage fails")
	require.Eventually(t, func() bool { return cache.LoadBinary("outbound_monitoring_history") != nil }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, m.UnsubscribeGroup("grp", events))
}

// A selection change (Selector.SelectOutbound -> SignalChange) must reach every group containing
// the selector and every group containing an outbound routed through it, re-test those
// dependents, and never block.
func TestH_MonitoringSignalChangePropagatesToDependents(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	b := &fakeOutbound{tag: "b"}
	selector := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, all: []string{"a", "b"}, selected: a}
	viaSelector := &fakeOutbound{tag: "c", deps: []string{"select"}}
	outer := &fakeGroup{fakeOutbound: fakeOutbound{tag: "outer"}, all: []string{"c"}, selected: viaSelector}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, a, b, selector, viaSelector, outer)
	require.NoError(t, m.Start(adapter.StartStateInitialize))

	done := make(chan error, 1)
	go func() {
		err := m.SignalChange("select")
		if err == nil {
			err = m.SignalChange("select") // notify channels already full: must not block
		}
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("SignalChange blocked")
	}

	for _, groupTag := range []string{"select", "", "outer"} {
		require.Len(t, m.reg().groups[groupTag].notifyCh, 1, "group %q not notified", groupTag)
	}
	require.True(t, m.reg().outbounds["c"].priorityQueued, "outbound routed through the selector is re-tested")
	require.False(t, m.reg().outbounds["a"].priorityQueued, "selector members did not change")
	require.False(t, m.reg().outbounds["b"].priorityQueued, "selector members did not change")

	require.Error(t, m.SignalChange("missing"))
}
