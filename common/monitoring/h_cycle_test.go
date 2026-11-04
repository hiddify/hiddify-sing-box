package monitoring

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The end of a cycle is told to every group, so a balancer that held its selection during it
// chooses with all the results.
func TestH_MonitoringTellsTheGroupsWhenACycleEnds(t *testing.T) {
	url, addr := noContentServer(t)
	a := &fakeOutbound{tag: "a", dial: dialTo(addr, nil)}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"a"}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{url},
		URLTestTimeout: badoption.Duration(time.Second),
	}, a, grp)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	events, err := m.SubscribeGroup("grp")
	require.NoError(t, err)
	defer m.UnsubscribeGroup("grp", events)
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart)) // runs the first cycle
	require.Eventually(t, func() bool { return !m.cycleRunning.Load() }, 5*time.Second, 10*time.Millisecond)
	for quiet := time.After(2 * time.Second); ; { // what the first cycle's results sent
		select {
		case <-events:
			continue
		case <-quiet:
		}
		break
	}

	m.cycleRunning.Store(true)
	m.endCycle()
	require.False(t, m.cycleRunning.Load())
	select {
	case <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("the end of the cycle was not told to the group")
	}
}

// Only a regular cycle of the schedule holds the groups: the first one after start and one after
// a network change are taken result by result. A network change during a regular cycle ends the
// hold, since its results are of the old network.
func TestH_MonitoringOnlyPeriodicCyclesHold(t *testing.T) {
	release := make(chan struct{})
	slow := &fakeOutbound{tag: "slow", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, context.DeadlineExceeded
	}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{"http://127.0.0.1:1/generate_204"},
		URLTestTimeout: badoption.Duration(5 * time.Second),
	}, slow)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	m.workerWG.Add(1)
	go m.workerLoop()

	require.True(t, m.startCycleOnce(), "as at start")
	require.True(t, m.cycleRunning.Load())
	require.False(t, m.PeriodicCycleRunning(), "the first cycle is taken as it comes")
	close(release)
	require.Eventually(t, func() bool { return !m.cycleRunning.Load() }, 10*time.Second, 10*time.Millisecond)

	release = make(chan struct{})
	require.True(t, m.startCycle(true), "the schedule's")
	require.True(t, m.PeriodicCycleRunning())
	m.started = true
	m.retestAll() // a network change during it
	require.False(t, m.PeriodicCycleRunning(), "the results are of the old network")
	close(release)
	require.Eventually(t, func() bool { return !m.cycleRunning.Load() }, 20*time.Second, 10*time.Millisecond)
	require.False(t, m.PeriodicCycleRunning())
}

// A member that starts working retests what goes through a group only when the group uses it:
// the Extra Security hop behind the selector was tested again for every member of a large
// subscription that answered.
func TestH_MonitoringGroupUsesItsSelectionOnly(t *testing.T) {
	a, b := &fakeOutbound{tag: "a"}, &fakeOutbound{tag: "b"}
	inner := &fakeGroup{fakeOutbound: fakeOutbound{tag: "inner"}, all: []string{"a", "b"}, selected: a}
	outer := &fakeGroup{fakeOutbound: fakeOutbound{tag: "outer"}, all: []string{"inner"}, selected: inner}
	m := newTestMonitor(t, nil, option.MonitoringOptions{Interval: badoption.Duration(time.Hour)}, a, b, inner, outer)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.True(t, m.groupUses("inner", "a"))
	require.False(t, m.groupUses("inner", "b"), "a member the group does not use")
	require.True(t, m.groupUses("outer", "a"), "through the group it selects")
	require.False(t, m.groupUses("outer", "b"))
	require.False(t, m.groupUses("a", "a"), "not a group")
}
