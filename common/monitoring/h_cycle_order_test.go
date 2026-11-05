package monitoring

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// A cycle tests the fastest members first, so the groups get the result of last run's best
// member first. Untested members have delay 0 and were sorted first, ahead of every cached one.
func TestH_MonitoringCycleTestsCachedFastestFirst(t *testing.T) {
	a, b, c, d := &fakeOutbound{tag: "a"}, &fakeOutbound{tag: "b"}, &fakeOutbound{tag: "c"}, &fakeOutbound{tag: "d"}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, a, b, c, d)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	setHistory(m, "b", 300, true, nil)
	setHistory(m, "c", 40, true, nil)
	setHistory(m, "d", 90, false, nil)
	for _, tag := range []string{"a", "b", "c", "d"} {
		m.reg().outbounds[tag].invalid = true
	}
	require.Equal(t, []string{"c", "a", "d", "b"}, m.collectCycleTargets(), "untested a after the fastest")
}

// A large subscription whose new members were all tested last waited a whole cycle of timeouts
// for them: they take every other place among the members that answered, by their delay, and
// the ones that failed come last.
func TestH_CycleOrderInterleavesUntested(t *testing.T) {
	t.Parallel()
	delays := map[string]uint16{"A": 10, "B": 12, "C": 15, "D": TimeoutDelay, "E": 0, "F": 0, "G": 0, "H": 0}
	require.Equal(t,
		[]string{"A", "E", "B", "F", "C", "G", "H", "D"},
		cycleOrder([]string{"D", "C", "E", "B", "F", "A", "G", "H"}, delays))
	require.Equal(t,
		[]string{"A", "E", "B", "C", "D"},
		cycleOrder([]string{"D", "C", "E", "B", "A"}, delays), "more answered than untested")
	require.Equal(t, []string{"x", "y"}, cycleOrder([]string{"x", "y"}, map[string]uint16{}), "all untested keep their order")
}

// The last run's timeouts loaded as untested, Delay 0, and with the untested members between the
// fastest they were tested before the new members. A cached timeout stays one and is tested last,
// however old; a cached ping orders the tests however old it is.
func TestH_CycleOrderOfLoadedHistory(t *testing.T) {
	now := time.Now()
	saved, err := json.Marshal(History{OutboundData: map[string]*adapter.URLTestHistory{
		"fast":     {Time: now.Add(-time.Hour), Delay: 40},
		"slow":     {Time: now.Add(-time.Hour), Delay: 300},
		"failed":   {Time: now.Add(-time.Hour), Delay: TimeoutDelay},
		"lastweek": {Time: now.Add(-7 * 24 * time.Hour), Delay: 10},
		"oldfail":  {Time: now.Add(-7 * 24 * time.Hour), Delay: TimeoutDelay},
	}})
	require.NoError(t, err)
	cache := &fakeCache{data: map[string]*adapter.SavedBinary{"outbound_monitoring_history": {Content: saved}}}
	var outbounds []adapter.Outbound
	for _, tag := range []string{"fast", "slow", "failed", "lastweek", "oldfail", "new"} {
		outbounds = append(outbounds, &fakeOutbound{tag: tag})
	}
	m := newTestMonitor(t, cache, option.MonitoringOptions{}, outbounds...)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	for _, tag := range []string{"fast", "slow", "failed", "lastweek", "oldfail", "new"} {
		m.reg().outbounds[tag].invalid = true
	}

	require.Equal(t, TimeoutDelay, m.getUrlTest("failed").Delay, "a cached timeout stays one")
	require.Equal(t, uint16(10), m.getUrlTest("lastweek").Delay, "an old ping is kept")

	require.Equal(t, []string{"lastweek", "new", "fast", "slow"}, m.collectCycleTargets()[:4], "the cached pings, fastest first, the untested between them")
	require.ElementsMatch(t, []string{"failed", "oldfail"}, m.collectCycleTargets()[4:], "the failures last")
}
