package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// fakeLazy is a lazy outbound as the monitoring sees it: it counts the tests' holds and the
// unloads asked for.
type fakeLazy struct {
	fakeOutbound
	held, peak, unloads atomic.Int32
}

func (f *fakeLazy) Loaded() bool { return f.held.Load() > 0 }
func (f *fakeLazy) Unload()      { f.unloads.Add(1) }
func (f *fakeLazy) Acquire() func() {
	if now := f.held.Add(1); now > f.peak.Load() {
		f.peak.Store(now)
	}
	return func() { f.held.Add(-1) }
}

// slowServer is noContentServer answering after a few milliseconds: a delay of 0 is no result.
func slowServer(t *testing.T) (string, M.Socksaddr) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server.URL + "/generate_204", M.ParseSocksaddr(server.Listener.Addr().String())
}

// delayOf is a ping of this run that worked, else 0.
func delayOf(m *OutboundMonitoring, group, tag string) uint16 {
	if his := m.OutboundsHistory(group)[tag]; his != nil && Worked(his.Delay, his.IsFromCache) {
		return his.Delay
	}
	return 0
}

// The lazy outbounds that keep top does not name rest: the cycles do not test them and the groups
// do not see them, so nothing dials through them. setActive tests the ones it takes out of rest
// and frees the ones it sends back.
func TestH_ParkedLazyOutbounds(t *testing.T) {
	link, addr := slowServer(t)
	lazies := make([]*fakeLazy, 4)
	outbounds := make([]adapter.Outbound, 0, 6)
	all := []string{"plain"}
	for i, tag := range []string{"a", "b", "c", "d"} {
		lazies[i] = &fakeLazy{fakeOutbound: fakeOutbound{tag: tag, dial: dialTo(addr, nil)}}
		outbounds = append(outbounds, lazies[i])
		all = append(all, tag)
	}
	plain := &fakeOutbound{tag: "plain", dial: dialTo(addr, nil)}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: all}
	outbounds = append(outbounds, plain, grp)
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		URLs:           []string{link},
		DebounceWindow: badoption.Duration(10 * time.Millisecond),
		URLTestTimeout: badoption.Duration(2 * time.Second),
	}, outbounds...)
	m.parkLazy.Store(true)
	m.setActive([]string{"a"}) // before the start: the first cycle tests it
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.True(t, m.Parked("b"))
	require.False(t, m.Parked("a"))
	require.False(t, m.Parked("plain"), "only a lazy outbound rests")
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))

	require.Eventually(t, func() bool { return delayOf(m, "", "a") > 0 && delayOf(m, "", "plain") > 0 }, 4*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return !m.cycleRunning.Load() }, 4*time.Second, 10*time.Millisecond)
	for _, tag := range []string{"b", "c", "d"} {
		require.Zero(t, delayOf(m, "", tag), "%s rests: the cycle does not test it", tag)
	}
	require.EqualValues(t, 0, lazies[1].peak.Load(), "nothing went through one that rests")
	require.EqualValues(t, 0, lazies[0].held.Load(), "the test's hold is over")
	require.EqualValues(t, 1, lazies[0].peak.Load(), "the test held it")

	// the next stage: a stays, b and c come
	m.setActive([]string{"a", "b", "c"})
	require.Eventually(t, func() bool { return delayOf(m, "", "b") > 0 && delayOf(m, "", "c") > 0 }, 4*time.Second, 10*time.Millisecond, "tested as they come out of rest")
	require.Zero(t, delayOf(m, "", "d"))
	members := m.OutboundsHistory("grp")
	require.Contains(t, members, "b")
	require.NotContains(t, members, "d", "a group does not see a member that rests")
	require.Contains(t, m.OutboundsHistory(""), "d", "the app does")

	// b is too slow for the top: back to rest, with its result
	m.setActive([]string{"a", "c"})
	require.True(t, m.Parked("b"))
	require.Eventually(t, func() bool { return lazies[1].unloads.Load() == 1 }, 2*time.Second, 5*time.Millisecond, "freed as it goes to rest")
	require.NotContains(t, m.OutboundsHistory("grp"), "b")
	rested := m.OutboundsHistory("")["b"]
	require.True(t, rested.Delay > 0 && rested.Delay < TimeoutDelay, "its last result stays for the app, as it was")
	require.EqualValues(t, 0, lazies[0].unloads.Load())

	// out of rest again: its old result is not a new one
	m.setActive([]string{"a", "b", "c"})
	require.Eventually(t, func() bool { return delayOf(m, "", "b") > 0 }, 4*time.Second, 10*time.Millisecond)

	// a test of the group is of the members in use; one asked for by its tag runs
	require.NoError(t, m.TestNow("grp"))
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, 0, lazies[3].peak.Load())
	require.NoError(t, m.TestNow("d"))
	require.Eventually(t, func() bool { return delayOf(m, "", "d") > 0 }, 4*time.Second, 10*time.Millisecond)

	// a list of them, at rest or not, is tested by the workers, and they stay at rest
	m.setActive([]string{"a"})
	setHistory(m, "b", 0, false, nil)
	setHistory(m, "c", 0, false, nil)
	m.TestOutbounds([]string{"b", "c", "grp", "ghost"}, "asked for")
	require.Eventually(t, func() bool { return delayOf(m, "", "b") > 0 && delayOf(m, "", "c") > 0 }, 4*time.Second, 10*time.Millisecond)
	require.True(t, m.Parked("b"))
	require.NotContains(t, m.OutboundsHistory("grp"), "b")
}

// Without keep top a lazy outbound is tested like any other.
func TestH_LazyOutboundsNotParkedByDefault(t *testing.T) {
	link, addr := slowServer(t)
	lazy := &fakeLazy{fakeOutbound: fakeOutbound{tag: "a", dial: dialTo(addr, nil)}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{URLs: []string{link}, URLTestTimeout: badoption.Duration(2 * time.Second)}, lazy)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.False(t, m.Parked("a"))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	require.Eventually(t, func() bool { return delayOf(m, "", "a") > 0 }, 4*time.Second, 10*time.Millisecond)
}

// A result from before the rest is not a result of the outbound taken out of it: it counts as a
// cached one until the new test is in, so what picks by this run's pings waits for that.
func TestH_ParkedResultIsCachedWhenTakenOutOfRest(t *testing.T) {
	link, addr := slowServer(t)
	gate := make(chan struct{})
	lazy := &fakeLazy{fakeOutbound: fakeOutbound{tag: "a", dial: dialTo(addr, func(ctx context.Context) error {
		select {
		case <-gate:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{URLs: []string{link}, URLTestTimeout: badoption.Duration(3 * time.Second)}, lazy)
	m.parkLazy.Store(true)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	setHistory(m, "a", 40, false, nil)

	m.setActive([]string{"a"})
	his := m.OutboundsHistory("")["a"]
	require.True(t, his.IsFromCache, "the old result, while the new test runs")
	require.EqualValues(t, 40, his.Delay)
	close(gate)
	require.Eventually(t, func() bool { return delayOf(m, "", "a") > 0 }, 4*time.Second, 10*time.Millisecond)

	m.setActive([]string{"a"}) // named again: nothing changes
	require.NotZero(t, delayOf(m, "", "a"))
}
