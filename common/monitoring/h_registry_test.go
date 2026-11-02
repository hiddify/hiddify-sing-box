package monitoring

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/hiddify/ipinfo"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

// A hot reload replaces an outbound by a new instance with the same tag: its last result stays, as
// a cached one, due for a test; an instance that stays keeps its result as it was.
func TestH_ReloadKeepsReplacedHistoryAsCache(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	b := &fakeOutbound{tag: "b"}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"a", "b"}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, a, b, grp)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	setHistory(m, "a", 120, false, &ipinfo.IpInfo{IP: "1.1.1.1"})
	setHistory(m, "b", 80, false, nil)
	m.reg().outbounds["a"].invalid = false
	m.reg().outbounds["b"].invalid = false

	manager := m.outboundManager.(*fakeOutboundManager)
	manager.list = []adapter.Outbound{&fakeOutbound{tag: "a"}, b, grp}
	require.NoError(t, m.Reload())

	replaced := m.reg().outbounds["a"]
	require.Equal(t, uint16(120), replaced.history.Delay, "the last result is kept")
	require.True(t, replaced.from_cache, "as a cached one")
	require.True(t, replaced.history.IpInfoFromCache)
	require.True(t, replaced.invalid, "and due for a test")
	require.True(t, m.getUrlTest("a").IsFromCache)
	require.Contains(t, m.collectCycleTargets(), "a")

	kept := m.reg().outbounds["b"]
	require.Equal(t, uint16(80), kept.history.Delay)
	require.False(t, kept.from_cache, "the same instance keeps its result as it was")
	require.False(t, kept.invalid)
	require.NotContains(t, m.collectCycleTargets(), "b")

	// no result yet: nothing to keep, and not from the cache
	manager.list = []adapter.Outbound{&fakeOutbound{tag: "a"}, &fakeOutbound{tag: "b"}, grp}
	setHistory(m, "b", 0, false, nil)
	require.NoError(t, m.Reload())
	require.False(t, m.reg().outbounds["b"].from_cache)
	require.Equal(t, []string{"a", "b"}, m.collectCycleTargets(), "the cached result sorts before the untested")
}

// A reload tests the outbounds it created or replaced, and only those: the others keep their
// result until their regular time, however old; and it does not wait for a cycle.
func TestH_ReloadTestsChangedOnly(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	b := &fakeOutbound{tag: "b"}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, a, b)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	m.started = true
	m.workerWG.Add(1)
	go m.workerLoop() // the tests run on the workers, started at post-start
	m.cycleSeq.Store(1)
	setHistory(m, "a", 120, false, nil)
	setHistory(m, "b", 80, false, nil)
	m.reg().outbounds["a"].invalid = false
	m.reg().outbounds["b"].invalid = false
	m.reg().outbounds["b"].history.Time = time.Now().Add(-time.Hour) // older than the interval

	manager := m.outboundManager.(*fakeOutboundManager)
	manager.list = []adapter.Outbound{&fakeOutbound{tag: "a"}, b}
	m.cycleRunning.Store(true) // a running cycle does not hold the changed outbound's test
	require.NoError(t, m.Reload())
	require.Eventually(t, func() bool {
		state := m.reg().outbounds["a"]
		state.mu.Lock()
		defer state.mu.Unlock()
		return !state.from_cache && state.history.Delay == TimeoutDelay
	}, 3*time.Second, 5*time.Millisecond, "the replaced outbound is tested (the fake dial fails)")
	time.Sleep(100 * time.Millisecond)
	kept := m.reg().outbounds["b"]
	kept.mu.Lock()
	defer kept.mu.Unlock()
	require.Equal(t, uint16(80), kept.history.Delay, "the outbound that stayed is not tested, however old its result")
	require.False(t, kept.queued)
	require.False(t, m.cycleAgain.Load(), "no cycle is asked for")
	m.cycleRunning.Store(false)
}

// The Touch that restarts the stopped timer workers counts as activity: it used to leave the old
// time in place, so the next tick stopped them again unless something else had touched since.
func TestH_TouchRestartRefreshesActivity(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, a)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	m.started = true
	stale := time.Now().Add(-time.Hour)
	m.lastActive.Store(stale)

	m.Touch()
	require.True(t, m.workersRunning.Load())
	require.True(t, m.lastActive.Load().After(stale))
}
