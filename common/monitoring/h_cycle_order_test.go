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
	require.Equal(t, []string{"c", "d", "b", "a"}, m.collectCycleTargets())
}
