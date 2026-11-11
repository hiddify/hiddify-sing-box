package monitoring

import (
	"context"
	"errors"
	"fmt"
	"slices"
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

// topLazy is a lazy outbound that answers after its delay, or not at all (below 0), and counts
// its tests.
type topLazy struct {
	fakeLazy
	delay atomic.Int64 // milliseconds
	tests atomic.Int32
}

func newTopLazy(tag string, addr M.Socksaddr, delay int64) *topLazy {
	lazy := &topLazy{}
	lazy.tag = tag
	lazy.delay.Store(delay)
	lazy.dial = dialTo(addr, func(ctx context.Context) error {
		lazy.tests.Add(1)
		delay := lazy.delay.Load()
		if delay < 0 {
			return errors.New("unreachable")
		}
		select {
		case <-time.After(time.Duration(delay) * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	return lazy
}

// pickSelector is a group the user selects in.
type pickSelector struct {
	fakeGroup
}

func (g *pickSelector) SelectOutbound(tag string) bool { return true }

// usedLazies are the lazy outbounds not at rest, sorted.
func usedLazies(m *OutboundMonitoring, lazies []*topLazy) []string {
	var used []string
	for _, lazy := range lazies {
		if !m.Parked(lazy.tag) {
			used = append(used, lazy.tag)
		}
	}
	slices.Sort(used)
	return used
}

func keptLazies(m *OutboundMonitoring) []string {
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	if k.picking || k.kept == nil {
		return nil
	}
	kept := make([]string, 0, len(k.kept))
	for tag := range k.kept {
		kept = append(kept, tag)
	}
	slices.Sort(kept)
	return kept
}

// Keep top goes through the lazy outbounds a batch at a time and ends on the fastest: never more
// in use than the kept ones and a batch, each tested once. Then: the one a selector selects is
// used in place of the slowest; when the kept ones die a new pick finds others; a replaced kept
// outbound, and a larger count, start a new pick that keeps the ones that answer; and without the
// option nothing rests.
func TestH_KeepTopPicksInStages(t *testing.T) {
	link, addr := slowServer(t)
	delays := map[int]int64{2: 120, 5: 60, 7: 10}
	var lazies []*topLazy
	var outbounds []adapter.Outbound
	var all []string
	for i := range 8 {
		delay, alive := delays[i]
		if !alive {
			delay = -1
		}
		lazy := newTopLazy(fmt.Sprint("p", i), addr, delay)
		lazies = append(lazies, lazy)
		outbounds = append(outbounds, lazy)
		all = append(all, lazy.tag)
	}
	plain := &fakeOutbound{tag: "plain", dial: dialTo(addr, nil)}
	selector := &pickSelector{fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, all: append([]string{"plain"}, all...), selected: plain}}
	outbounds = append(outbounds, plain, selector)
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		URLs:           []string{link},
		Interval:       badoption.Duration(time.Hour),
		DebounceWindow: badoption.Duration(10 * time.Millisecond),
		URLTestTimeout: badoption.Duration(2 * time.Second),
		KeepTop:        &option.KeepTopOptions{Count: 2, Batch: 3},
	}, outbounds...)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.Equal(t, []string{"p0", "p1", "p2"}, usedLazies(m, lazies), "the first stage: a batch, in the config's order")
	require.True(t, m.KeepTopSearching())
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))

	most := 0
	require.Eventually(t, func() bool {
		most = max(most, len(usedLazies(m, lazies)))
		return keptLazies(m) != nil
	}, 20*time.Second, 2*time.Millisecond, "the pick ends")
	require.LessOrEqual(t, most, 5, "never more in use than the two kept and a batch of three")
	require.Equal(t, []string{"p5", "p7"}, keptLazies(m), "the two fastest")
	require.Equal(t, []string{"p5", "p7"}, usedLazies(m, lazies))
	require.False(t, m.KeepTopSearching())
	members := m.OutboundsHistory("select")
	require.Contains(t, members, "p7")
	require.Contains(t, members, "plain", "what is not lazy is not its business")
	require.NotContains(t, members, "p2", "too slow for the top: it rests, though it answers")
	for _, lazy := range lazies {
		require.EqualValues(t, 1, lazy.tests.Load(), "%s is tested once in a pick", lazy.tag)
		require.LessOrEqual(t, lazy.peak.Load(), int32(1))
	}

	// selected by the user while it rests: used, beside the kept ones
	selector.selected = lazies[2]
	require.NoError(t, m.SignalChange("select"))
	require.Equal(t, []string{"p2", "p5", "p7"}, usedLazies(m, lazies))
	selector.selected = plain
	require.NoError(t, m.SignalChange("select"))
	require.Equal(t, []string{"p5", "p7"}, usedLazies(m, lazies), "no longer selected: the fastest two again")
	// with room for more, one that was only selected still leaves when it is not: the pick did
	// not choose it (it may be of another country)
	m.SetKeepTop(&option.KeepTopOptions{Count: 4, Batch: 3})
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"p2", "p5", "p7"}) }, 30*time.Second, 5*time.Millisecond)
	lazies[2].delay.Store(-1)
	selector.selected = lazies[3]
	require.NoError(t, m.SignalChange("select"))
	require.Equal(t, []string{"p2", "p3", "p5", "p7"}, usedLazies(m, lazies))
	selector.selected = plain
	require.NoError(t, m.SignalChange("select"))
	require.Equal(t, []string{"p2", "p5", "p7"}, usedLazies(m, lazies), "p3 leaves though only three of four are kept")
	lazies[2].delay.Store(120)
	m.SetKeepTop(&option.KeepTopOptions{Count: 2, Batch: 3})
	require.Equal(t, []string{"p5", "p7"}, usedLazies(m, lazies))
	selector.selected = lazies[2]
	require.NoError(t, m.SignalChange("select"))

	// the kept ones die, others work now: a new pick finds them
	lazies[2].delay.Store(-1)
	lazies[7].delay.Store(-1)
	lazies[0].delay.Store(30)
	lazies[1].delay.Store(40)
	lazies[5].delay.Store(-1)
	selector.selected = plain
	require.NoError(t, m.TestNow("p2"))
	require.NoError(t, m.TestNow("p5"))
	require.NoError(t, m.TestNow("p7"))
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"p0", "p1"}) }, 30*time.Second, 5*time.Millisecond)
	lazies[5].delay.Store(90)

	// a kept outbound is replaced by a hot reload: a new pick, which keeps the one that answers
	replaced := newTopLazy("p0", addr, -1)
	manager := m.outboundManager.(*fakeOutboundManager)
	manager.list = append([]adapter.Outbound{replaced}, manager.list[1:]...)
	lazies[0] = replaced
	require.NoError(t, m.Reload())
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"p1", "p5"}) }, 30*time.Second, 5*time.Millisecond)

	// pinned by the options: used like a selected one, beside the fastest, and tested
	m.SetKeepTop(&option.KeepTopOptions{Count: 2, Batch: 3, Pinned: []string{"p3", "ghost"}})
	require.Equal(t, []string{"p1", "p3", "p5"}, usedLazies(m, lazies))
	require.Eventually(t, func() bool { return lazies[3].tests.Load() >= 2 }, 10*time.Second, 5*time.Millisecond, "tested as it comes out of rest")
	m.SetKeepTop(&option.KeepTopOptions{Count: 2, Batch: 3})
	require.Equal(t, []string{"p1", "p5"}, usedLazies(m, lazies), "no longer pinned: the fastest two alone")

	// fewer to keep: the fastest of them, with no new test
	tests := lazies[1].tests.Load() + lazies[5].tests.Load()
	m.SetKeepTop(&option.KeepTopOptions{Count: 1, Batch: 3})
	require.Equal(t, []string{"p1"}, keptLazies(m))
	require.Equal(t, tests, lazies[1].tests.Load()+lazies[5].tests.Load())

	// more than there are that answer: all of those
	m.SetKeepTop(&option.KeepTopOptions{Count: 5, Batch: 10})
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"p1", "p5"}) }, 30*time.Second, 5*time.Millisecond)

	// off: nothing rests
	m.SetKeepTop(nil)
	require.Len(t, usedLazies(m, lazies), 8)
	require.Contains(t, m.OutboundsHistory("select"), "p3")
}

// When none answers, keep top goes through them again, not faster than its hold, and goes on as
// soon as one of those in use answers.
func TestH_KeepTopNoneAnswers(t *testing.T) {
	link, addr := slowServer(t)
	var lazies []*topLazy
	var outbounds []adapter.Outbound
	for i := range 3 {
		lazy := newTopLazy(fmt.Sprint("p", i), addr, -1)
		lazies = append(lazies, lazy)
		outbounds = append(outbounds, lazy)
	}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		URLs:           []string{link},
		Interval:       badoption.Duration(time.Hour),
		URLTestTimeout: badoption.Duration(2 * time.Second),
		KeepTop:        &option.KeepTopOptions{Count: 1, Batch: 2},
	}, outbounds...)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	round := func() int {
		m.keepTop.access.Lock()
		defer m.keepTop.access.Unlock()
		return m.keepTop.round
	}
	require.Eventually(t, func() bool { return round() == 1 }, 20*time.Second, 5*time.Millisecond, "all were gone through")
	require.False(t, m.KeepTopSearching(), "none is available now")
	require.Equal(t, []string{"p0", "p1"}, usedLazies(m, lazies), "the groups keep something to use")
	require.Eventually(t, func() bool { return lazies[0].tests.Load() == 2 && lazies[1].tests.Load() == 2 }, 20*time.Second, 5*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, 1, round(), "it holds: no other round at once")
	require.EqualValues(t, 1, lazies[2].tests.Load())

	lazies[1].delay.Store(20)
	require.NoError(t, m.TestNow("p1"))
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"p1"}) }, 20*time.Second, 5*time.Millisecond, "one answers: the pick goes on")
	require.Equal(t, 0, round())
}

// keep_top with answering keeps every lazy outbound that answers, and drops one that stops.
func TestH_KeepTopAnswering(t *testing.T) {
	link, addr := slowServer(t)
	var lazies []*topLazy
	var outbounds []adapter.Outbound
	for i, delay := range []int64{10, -1, 30} {
		lazy := newTopLazy(fmt.Sprint("p", i), addr, delay)
		lazies = append(lazies, lazy)
		outbounds = append(outbounds, lazy)
	}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		URLs:           []string{link},
		Interval:       badoption.Duration(time.Hour),
		URLTestTimeout: badoption.Duration(2 * time.Second),
		KeepTop:        &option.KeepTopOptions{Answering: true},
	}, outbounds...)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"p0", "p2"}) }, 20*time.Second, 5*time.Millisecond)
	lazies[2].delay.Store(-1)
	require.NoError(t, m.TestNow("p2"))
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"p0"}) }, 20*time.Second, 5*time.Millisecond)
}

// Fewer lazy outbounds than the count: nothing rests, and nothing is picked.
func TestH_KeepTopNothingToLeaveOut(t *testing.T) {
	link, addr := slowServer(t)
	a, b := newTopLazy("a", addr, 5), newTopLazy("b", addr, 5)
	m := newTestMonitor(t, nil, option.MonitoringOptions{URLs: []string{link}, KeepTop: &option.KeepTopOptions{Count: 3}}, a, b)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.False(t, m.Parked("a"))
	require.False(t, m.Parked("b"))
	require.False(t, m.KeepTopSearching())
}

// The pings of a run are in the cache: the next run starts with the ones that answered, fastest
// first, though they are last in the config.
func TestH_KeepTopStartsWithTheFastestOfTheLastRun(t *testing.T) {
	link, addr := slowServer(t)
	cache := &fakeCache{data: map[string]*adapter.SavedBinary{}}
	run := func() (*OutboundMonitoring, []*topLazy) {
		var lazies []*topLazy
		var outbounds []adapter.Outbound
		for i, delay := range []int64{-1, -1, -1, -1, 80, 20} {
			lazy := newTopLazy(fmt.Sprint("p", i), addr, delay)
			lazies = append(lazies, lazy)
			outbounds = append(outbounds, lazy)
		}
		m := newTestMonitor(t, cache, option.MonitoringOptions{
			URLs:           []string{link},
			Interval:       badoption.Duration(time.Hour),
			URLTestTimeout: badoption.Duration(2 * time.Second),
			KeepTop:        &option.KeepTopOptions{Count: 1, Batch: 2},
		}, outbounds...)
		require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
		return m, lazies
	}
	first, lazies := run()
	require.Equal(t, []string{"p0", "p1"}, usedLazies(first, lazies), "nothing known: the config's order")
	require.NoError(t, htest.Start(first, adapter.StartStatePostStart))
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(first), []string{"p5"}) }, 20*time.Second, 5*time.Millisecond)
	require.NotNil(t, cache.LoadBinary("outbound_monitoring_history"), "saved as the pick goes, not only at the close")

	second, lazies := run()
	require.Equal(t, []string{"p4", "p5"}, usedLazies(second, lazies), "the two that answered")
}
