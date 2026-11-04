package monitoring

import (
	"context"
	"errors"
	"net"
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

// A test whose dial never returns, ignoring its deadline, is given up on after the hard limit:
// it counts as failed and the worker tests the next outbound. It used to hold the worker, and the
// cycle waiting for it, for good.
func TestH_MonitoringGivesUpOnATestThatNeverReturns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddr := M.ParseSocksaddr(server.Listener.Addr().String())
	release := make(chan struct{})
	defer close(release)
	stuck := &fakeOutbound{tag: "stuck", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		<-release // the deadline in ctx is ignored, as a dial into a native library may
		return nil, context.DeadlineExceeded
	}}
	var dialer net.Dialer
	good := &fakeOutbound{tag: "good", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination != serverAddr {
			return nil, context.DeadlineExceeded
		}
		return dialer.DialContext(ctx, network, destination.String())
	}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{server.URL + "/generate_204"},
		URLTestTimeout: badoption.Duration(100 * time.Millisecond),
	}, stuck, good)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	// one worker and no cycle: the stuck test must not keep the good one from running
	m.workerWG.Add(1)
	go m.workerLoop()

	delay := func(tag string) uint16 {
		state := m.reg().outbounds[tag]
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history.Delay
	}
	// InvalidateTest: a priority test with the one timeout, as a balancer asks for after a failed
	// connection; a staged test ends at its own deadline instead
	require.NoError(t, m.InvalidateTest("stuck"))
	require.NoError(t, m.TestNow("good"))
	limit := m.testHardLimit(&testTask{})
	require.Eventually(t, func() bool { d := delay("good"); return d > 0 && d < TimeoutDelay }, time.Second, 10*time.Millisecond,
		"a test asked for runs at once, beside the stuck one, not behind it")
	require.Eventually(t, func() bool { return delay("stuck") == TimeoutDelay }, limit+2*time.Second, 10*time.Millisecond,
		"the test that never returns counts as failed after %s", limit)
	require.Eventually(t, func() bool { return !m.reg().outbounds["stuck"].testing }, time.Second, 10*time.Millisecond,
		"the outbound is free to be tested again")
}

// The delay a URL test measured shows as soon as it answers, before the IP lookup that follows
// it, which can take as long again; the IP comes when the lookup is done.
func TestH_MonitoringPublishesTheDelayBeforeTheIPLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddr := M.ParseSocksaddr(server.Listener.Addr().String())
	var dialer net.Dialer
	slowIP := &fakeOutbound{tag: "slow-ip", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination != serverAddr { // the IP services: slow, then unreachable
			select {
			case <-ctx.Done():
			case <-time.After(1500 * time.Millisecond):
			}
			return nil, context.DeadlineExceeded
		}
		return dialer.DialContext(ctx, network, destination.String())
	}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{server.URL + "/generate_204"},
		URLTestTimeout: badoption.Duration(2 * time.Second),
	}, slowIP)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))

	start := time.Now()
	require.NoError(t, m.TestNow("slow-ip"))
	require.Eventually(t, func() bool {
		state := m.reg().outbounds["slow-ip"]
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history.Delay > 0 && state.history.Delay < TimeoutDelay
	}, time.Second, 5*time.Millisecond, "the delay shows before the IP lookup is done")
	require.Less(t, time.Since(start), time.Second)
	require.True(t, m.reg().outbounds["slow-ip"].testing, "the IP lookup still runs")
}

// A test asked for runs in stages: a miss at the first mark shows at once, as unavailable for
// now, while a second attempt starts; the first answer from any attempt wins, however late; and
// the groups never see the miss, only the last confirmed result, so none takes the member for
// dead on it.
func TestH_MonitoringStagedTestShowsTheMissThenTheAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddr := M.ParseSocksaddr(server.Listener.Addr().String())
	var dialer net.Dialer
	// answers after 450 ms: past the first mark, before the second
	var dialDelay, dials atomic.Int64
	dialDelay.Store(int64(450 * time.Millisecond))
	slow := &fakeOutbound{tag: "slow"}
	slow.dial = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination != serverAddr {
			return nil, context.DeadlineExceeded
		}
		dials.Add(1)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(dialDelay.Load())):
		}
		return dialer.DialContext(ctx, network, destination.String())
	}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"slow"}, selected: slow}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:         badoption.Duration(time.Hour),
		Workers:          1,
		URLs:             []string{server.URL + "/generate_204"},
		URLTestTimeout:   badoption.Duration(2 * time.Second),
		OnDemandTimeouts: []badoption.Duration{badoption.Duration(200 * time.Millisecond), badoption.Duration(800 * time.Millisecond), badoption.Duration(3 * time.Second)},
	}, slow, grp)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	setHistory(m, "slow", 70, true, nil) // only the previous run's result: nothing of this run is known

	start := time.Now()
	require.NoError(t, m.TestNow("slow"))
	appSees := func() uint16 { return m.OutboundsHistory("")["slow"].Delay }
	groupSees := func() uint16 { return m.OutboundsHistory("grp")["slow"].Delay }
	require.Eventually(t, func() bool { return appSees() == TimeoutDelay }, time.Second, 5*time.Millisecond, "a miss at the first mark shows as unavailable")
	require.Less(t, time.Since(start), 400*time.Millisecond)
	require.Eventually(t, func() bool { d := appSees(); return d > 0 && d < TimeoutDelay }, time.Second, 5*time.Millisecond, "the first attempt's late answer shows at once")
	require.Less(t, time.Since(start), 700*time.Millisecond, "not waiting for the deadline")
	require.Equal(t, appSees(), groupSees(), "the answer is confirmed for the group too")
	require.Equal(t, int64(1), dials.Load(), "a slow proxy is pinged once: no second attempt beside one still running")

	// the outbound worked in this run: the first mark does not apply, its result stays through
	// the slow answer, and the answer replaces it; a miss would come at the second mark
	setHistory(m, "slow", 70, false, nil)
	start = time.Now()
	require.NoError(t, m.TestNow("slow"))
	require.Eventually(t, func() bool { d := appSees(); return d != 70 }, time.Second, 5*time.Millisecond, "the answer shows")
	require.Less(t, appSees(), TimeoutDelay, "a working outbound is not shown as unavailable at the first mark")
	require.Greater(t, time.Since(start), 400*time.Millisecond, "the answer came from the first attempt")
	require.Equal(t, appSees(), groupSees())

	// the outbound worked in this run and answers only after the second mark: the miss shows
	// there, not at the first, and the group keeps the last confirmed result through it
	dialDelay.Store(int64(900 * time.Millisecond))
	setHistory(m, "slow", 70, false, nil)
	start = time.Now()
	require.NoError(t, m.TestNow("slow"))
	require.Eventually(t, func() bool { return appSees() == TimeoutDelay }, 2*time.Second, 5*time.Millisecond, "a miss at the second mark shows as unavailable")
	require.Greater(t, time.Since(start), 700*time.Millisecond, "not at the first mark")
	require.Equal(t, uint16(70), groupSees(), "the group keeps the last confirmed result through the miss")
	require.Eventually(t, func() bool { d := appSees(); return d > 0 && d < TimeoutDelay }, 2*time.Second, 5*time.Millisecond, "the late answer shows at once")
	require.Equal(t, appSees(), groupSees(), "the answer is confirmed for the group too")
	require.Equal(t, int64(3), dials.Load(), "one ping per test")

	// every attempt fails at once: over as soon as the last one has, not at the deadline
	dead := &fakeOutbound{tag: "dead"}
	m2 := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:         badoption.Duration(time.Hour),
		Workers:          1,
		URLs:             []string{server.URL + "/generate_204"},
		OnDemandTimeouts: []badoption.Duration{badoption.Duration(200 * time.Millisecond), badoption.Duration(400 * time.Millisecond), badoption.Duration(10 * time.Second)},
	}, dead)
	require.NoError(t, htest.Start(m2, adapter.StartStateInitialize))
	start = time.Now()
	require.NoError(t, m2.TestNow("dead"))
	require.Eventually(t, func() bool {
		state := m2.reg().outbounds["dead"]
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history.Delay == TimeoutDelay && !state.tentative
	}, 2*time.Second, 5*time.Millisecond, "failed for good once the last attempt failed")
	require.Less(t, time.Since(start), 1500*time.Millisecond, "not waiting for the deadline")
}

// A member whose only result is the one cached from the previous run has nothing to keep through
// a miss: the groups see the miss, so lowest-delay leaves a cached pick that does not answer for
// one that does. They used to keep the cached result, marked as fresh, and stayed on a member the
// app showed as not responding while others worked.
func TestH_MonitoringMissOfACachedMemberIsSeenByTheGroups(t *testing.T) {
	never := &fakeOutbound{tag: "cached", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"cached"}, selected: never}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:         badoption.Duration(time.Hour),
		Workers:          1,
		URLs:             []string{"http://127.0.0.1:1/generate_204"},
		URLTestTimeout:   badoption.Duration(2 * time.Second),
		OnDemandTimeouts: []badoption.Duration{badoption.Duration(200 * time.Millisecond), badoption.Duration(800 * time.Millisecond), badoption.Duration(3 * time.Second)},
	}, never, grp)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	setHistory(m, "cached", 70, true, nil) // only the previous run's result

	require.NoError(t, m.TestNow("cached"))
	groupSees := func() uint16 { return m.OutboundsHistory("grp")["cached"].Delay }
	require.Eventually(t, func() bool { return m.OutboundsHistory("")["cached"].Delay == TimeoutDelay }, time.Second, 5*time.Millisecond)
	require.Equal(t, TimeoutDelay, groupSees(), "nothing of this run to keep: the group sees the miss")
}

// A failed attempt is tried again at the next mark, and so until the last mark: a proxy that
// fails twice and then answers is found working by the third attempt, with no attempt started
// beside a running one.
func TestH_MonitoringStagedTestRetriesOnlyAFailedAttempt(t *testing.T) {
	url, addr := noContentServer(t)
	var dials atomic.Int64
	flaky := &fakeOutbound{tag: "flaky", dial: dialTo(addr, func(ctx context.Context) error {
		if dials.Add(1) < 3 {
			return errors.New("connection refused")
		}
		time.Sleep(20 * time.Millisecond) // a measurable delay: a 0 ms answer counts as none
		return nil
	})}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:         badoption.Duration(time.Hour),
		Workers:          1,
		URLs:             []string{url},
		OnDemandTimeouts: []badoption.Duration{badoption.Duration(200 * time.Millisecond), badoption.Duration(400 * time.Millisecond), badoption.Duration(3 * time.Second)},
	}, flaky)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	start := time.Now()
	require.NoError(t, m.TestNow("flaky"))
	appSees := func() uint16 { return m.OutboundsHistory("")["flaky"].Delay }
	require.Eventually(t, func() bool { return appSees() == TimeoutDelay }, time.Second, 5*time.Millisecond, "the failed first attempt shows as unavailable at once")
	require.Less(t, time.Since(start), 150*time.Millisecond)
	require.Eventually(t, func() bool { d := appSees(); return d > 0 && d < TimeoutDelay }, 2*time.Second, 5*time.Millisecond, "the third attempt answers")
	require.Greater(t, time.Since(start), 380*time.Millisecond, "the third attempt started at the second mark")
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, int64(3), dials.Load(), "one attempt per mark, each after a failure")
}
