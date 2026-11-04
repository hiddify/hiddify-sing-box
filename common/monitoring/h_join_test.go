package monitoring

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// A test asked for while a test of the same outbound runs joins it: one ping, one result for
// both. Two tests at once pinged the proxy twice and the last to end wrote the result.
func TestH_MonitoringTestJoinsTheRunningOne(t *testing.T) {
	url, addr := noContentServer(t)
	var dials, inFlight, maxInFlight atomic.Int64
	slow := &fakeOutbound{tag: "slow", dial: dialTo(addr, func(ctx context.Context) error {
		dials.Add(1)
		if n := inFlight.Add(1); n > maxInFlight.Load() {
			maxInFlight.Store(n)
		}
		defer inFlight.Add(-1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
			return nil
		}
	})}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:         badoption.Duration(time.Hour),
		Workers:          2,
		URLs:             []string{url},
		OnDemandTimeouts: []badoption.Duration{badoption.Duration(time.Second), badoption.Duration(3 * time.Second), badoption.Duration(10 * time.Second)},
	}, slow)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))

	// the cycle's test of it (run by a worker), and a tap on it while that runs
	results := make(chan testOutcome, 1)
	go m.executeTask(&testTask{outboundTag: "slow", cycleID: m.cycleSeq.Add(1), resultCh: results})
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, m.TestNow("slow"))
	select {
	case outcome := <-results:
		require.NoError(t, outcome.err)
	case <-time.After(3 * time.Second):
		t.Fatal("the cycle's test did not end")
	}
	require.Eventually(t, m.reg().outbounds["slow"].tested, 2*time.Second, 5*time.Millisecond, "both tests are over")
	his := m.OutboundsHistory("")["slow"]
	require.NotNil(t, his)
	require.Greater(t, his.Delay, uint16(0))
	require.Less(t, his.Delay, TimeoutDelay)
	require.Equal(t, int64(1), dials.Load(), "one ping for both")
	require.Equal(t, int64(1), maxInFlight.Load(), "never two tests of one outbound at once")

	// a tap during a tap
	dials.Store(0)
	require.NoError(t, m.TestNow("slow"))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, m.TestNow("slow"))
	require.Eventually(t, m.reg().outbounds["slow"].tested, 2*time.Second, 5*time.Millisecond)
	require.Equal(t, int64(1), dials.Load(), "the second tap joined the first")
	require.Equal(t, int64(1), maxInFlight.Load())
}
