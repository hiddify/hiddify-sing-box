package monitoring

import (
	"context"
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

// hReadyOutbound is connecting until ready is set, like Psiphon before its tunnel is up.
type hReadyOutbound struct {
	fakeOutbound
	ready atomic.Bool
}

func (o *hReadyOutbound) Status() adapter.Status {
	if o.ready.Load() {
		return adapter.StatusReady
	}
	return adapter.StatusConnecting
}

// A URL test asked for while the outbound is still connecting runs once it is ready, and later
// URL tests of it still run: the skipped test used to leave it marked as queued, so every URL test
// of it after that was dropped.
func TestH_MonitoringPriorityTestOfConnectingOutbound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond) // a 0 ms delay would read as "not measured"
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var dialer net.Dialer
	hop := &hReadyOutbound{fakeOutbound: fakeOutbound{tag: "hop", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return dialer.DialContext(ctx, network, destination.String())
	}}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{server.URL + "/generate_204"},
		URLTestTimeout: badoption.Duration(time.Second),
	}, hop)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	// the workers only: no regular cycle, which would test it too
	m.workerWG.Add(1)
	go m.workerLoop()

	tested := func() bool {
		state := m.reg().outbounds["hop"]
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history.Delay > 0 && state.history.Delay < TimeoutDelay
	}
	require.NoError(t, m.TestNow("hop"))
	require.Never(t, tested, 500*time.Millisecond, 10*time.Millisecond, "a connecting outbound is not tested")
	hop.ready.Store(true)
	require.Eventually(t, tested, 5*time.Second, 10*time.Millisecond, "the skipped URL test runs once it is ready")

	setHistory(m, "hop", 0, false, nil)
	require.NoError(t, m.TestNow("hop"))
	require.Eventually(t, tested, 2*time.Second, 10*time.Millisecond, "a later URL test runs too")
}
