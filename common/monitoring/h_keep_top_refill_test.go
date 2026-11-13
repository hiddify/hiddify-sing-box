package monitoring

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func refillMonitor(t *testing.T, keepTop *option.KeepTopOptions, delays []int64) (*OutboundMonitoring, []*topLazy) {
	link, addr := slowServer(t)
	var lazies []*topLazy
	var outbounds []adapter.Outbound
	for i, delay := range delays {
		lazy := newTopLazy(fmt.Sprint("p", i), addr, delay)
		lazies = append(lazies, lazy)
		outbounds = append(outbounds, lazy)
	}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		URLs:           []string{link},
		Interval:       badoption.Duration(time.Hour),
		URLTestTimeout: badoption.Duration(2 * time.Second),
		KeepTop:        keepTop,
	}, outbounds...)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	return m, lazies
}

func keptAre(m *OutboundMonitoring, tags ...string) func() bool {
	return func() bool { return slices.Equal(keptLazies(m), tags) }
}

func setRecheckWait(t *testing.T, wait time.Duration) {
	previous := keepTopRecheckWait
	keepTopRecheckWait = func(int) time.Duration { return wait }
	t.Cleanup(func() { keepTopRecheckWait = previous })
}

func init() { keepTopRetestAfter = 50 * time.Millisecond }

func TestH_KeepTopRecheckWait(t *testing.T) {
	for rechecks, wait := range []time.Duration{10 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour, 6 * time.Hour} {
		require.Equal(t, wait, keepTopRecheckWait(rechecks))
	}
	require.Equal(t, 6*time.Hour, keepTopRecheckWait(50))
}

// One failed test does not cost a kept outbound its place: it is tested once more, and stays
// when that test answers.
func TestH_KeepTopOneFailedTestKeepsThePlace(t *testing.T) {
	setRecheckWait(t, time.Hour)
	m, lazies := refillMonitor(t, &option.KeepTopOptions{Count: 2, Batch: 1}, []int64{10, 20, 30, -1})
	require.Eventually(t, keptAre(m, "p0", "p1"), 20*time.Second, 5*time.Millisecond)
	lazies[1].delay.Store(-1)
	require.NoError(t, m.TestNow("p1"))
	require.Eventually(t, func() bool { return lazies[1].tests.Load() >= 2 }, 20*time.Second, time.Millisecond, "the test that fails")
	lazies[1].delay.Store(20)
	require.Eventually(t, func() bool { return lazies[1].tests.Load() >= 3 }, 20*time.Second, 5*time.Millisecond, "tested once more")
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, []string{"p0", "p1"}, keptLazies(m))
	require.EqualValues(t, 1, lazies[2].tests.Load(), "no pick for one failed test")
}

// With a count, a kept outbound that stops answering is replaced by the next that answers,
// without testing all the ones at rest; with none to take its place, the ones at rest are tested
// again later, and the one that answers then is used.
func TestH_KeepTopRefillsAPlace(t *testing.T) {
	setRecheckWait(t, time.Hour)
	m, lazies := refillMonitor(t, &option.KeepTopOptions{Count: 2, Batch: 1}, []int64{10, 20, 30, -1, -1, -1})
	require.Eventually(t, keptAre(m, "p0", "p1"), 20*time.Second, 5*time.Millisecond)
	m.keepTop.access.Lock()
	require.True(t, m.keepTop.recheckAt.IsZero(), "all the places are taken: nothing to look for")
	m.keepTop.access.Unlock()

	lazies[1].delay.Store(-1)
	require.NoError(t, m.TestNow("p1"))
	require.Eventually(t, keptAre(m, "p0", "p2"), 20*time.Second, 5*time.Millisecond, "the next that answers takes the place")
	require.EqualValues(t, 1, lazies[5].tests.Load(), "the pick ended once the place was filled")
	require.EqualValues(t, 1, lazies[0].tests.Load(), "the one that answers is not tested again")

	// none at rest answers: one fewer is kept, and they are tested again after the wait
	setRecheckWait(t, 300*time.Millisecond)
	lazies[2].delay.Store(-1)
	require.NoError(t, m.TestNow("p2"))
	require.Eventually(t, keptAre(m, "p0"), 20*time.Second, 5*time.Millisecond)
	rechecks := func() int {
		m.keepTop.access.Lock()
		defer m.keepTop.access.Unlock()
		return m.keepTop.rechecks
	}
	require.Eventually(t, func() bool { return rechecks() >= 2 }, 30*time.Second, 5*time.Millisecond, "nothing came back: the wait grows")
	lazies[1].delay.Store(20)
	require.Eventually(t, keptAre(m, "p0", "p1"), 30*time.Second, 5*time.Millisecond, "it answers again: it is used again")
	require.Equal(t, 0, rechecks())
}

// With answering, an outbound that rests because it did not answer is used again when it answers
// a later test of the ones at rest, or a test asked for by its tag.
func TestH_KeepTopAnsweringComesBack(t *testing.T) {
	setRecheckWait(t, time.Hour)
	m, lazies := refillMonitor(t, &option.KeepTopOptions{Answering: true}, []int64{10, -1, 30})
	require.Eventually(t, keptAre(m, "p0", "p2"), 20*time.Second, 5*time.Millisecond)

	// the user tests the list: the one that answers now comes out of rest
	lazies[1].delay.Store(20)
	m.TestOutbounds([]string{"p1"}, "test")
	require.Eventually(t, keptAre(m, "p0", "p1", "p2"), 20*time.Second, 5*time.Millisecond)
	require.False(t, m.Parked("p1"))

	// it stops, rests, and answers again: found by the next test of the ones at rest
	setRecheckWait(t, 300*time.Millisecond)
	lazies[2].delay.Store(-1)
	require.NoError(t, m.TestNow("p2"))
	require.Eventually(t, keptAre(m, "p0", "p1"), 20*time.Second, 5*time.Millisecond)
	tests := lazies[0].tests.Load()
	lazies[2].delay.Store(30)
	require.Eventually(t, keptAre(m, "p0", "p1", "p2"), 30*time.Second, 5*time.Millisecond)
	require.Equal(t, tests, lazies[0].tests.Load(), "the ones in use are not tested for it")
}
