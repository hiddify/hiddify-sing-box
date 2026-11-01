package monitoring

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The outbound a group's selection leads to is tested before the first cycle, whatever the cycle's
// order, and again at once when the selection moves: its ping is the one the user looks at.
func TestH_MonitoringTestsTheSelectionFirstAndOnChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddr := M.ParseSocksaddr(server.Listener.Addr().String())
	var (
		dialer net.Dialer
		mu     sync.Mutex
		dials  []string
	)
	outbound := func(tag string) *fakeOutbound {
		return &fakeOutbound{tag: tag, dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if destination != serverAddr {
				return nil, context.DeadlineExceeded
			}
			mu.Lock()
			dials = append(dials, tag)
			mu.Unlock()
			return dialer.DialContext(ctx, network, destination.String())
		}}
	}
	dialed := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), dials...)
	}
	a, b := outbound("a"), outbound("b")
	// a answers slowly: the one worker is busy with it for a while
	slowDial := a.dial
	a.dial = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		time.Sleep(300 * time.Millisecond)
		return slowDial(ctx, network, destination)
	}
	selector := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, all: []string{"a", "b"}, selected: b}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{server.URL + "/generate_204"},
		URLTestTimeout: badoption.Duration(time.Second),
		DebounceWindow: badoption.Duration(10 * time.Millisecond),
	}, a, b, selector)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	// last run: a was the faster one, so the cycle alone would test it first
	stale := time.Now().Add(-2 * time.Hour)
	for tag, delay := range map[string]uint16{"a": 50, "b": 300} {
		state := m.reg().outbounds[tag]
		state.mu.Lock()
		state.history = adapter.URLTestHistory{Delay: delay, Time: stale}
		state.from_cache = true
		state.mu.Unlock()
	}
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))

	// the selected member has its result while the worker is still busy with the faster one
	require.Eventually(t, func() bool { return m.reg().outbounds["b"].tested() }, 250*time.Millisecond, 5*time.Millisecond,
		"the selected member is tested at once, beside the cycle")
	require.False(t, m.reg().outbounds["a"].tested(), "the cycle's test of the faster one is still running")

	// the selection moves to a: it is tested again at once, though its result is fresh
	require.Eventually(t, func() bool { return m.reg().outbounds["a"].tested() }, 5*time.Second, 10*time.Millisecond)
	before := len(dialed())
	selector.selected = a
	require.NoError(t, m.SignalChange("select"))
	require.Eventually(t, func() bool {
		d := dialed()
		return len(d) > before && d[len(d)-1] == "a"
	}, 5*time.Second, 10*time.Millisecond, "the new selection is tested on the change")
}
