package monitoring

import (
	"testing"

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
