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

// P1 dials through P2 (here through a selector holding P2): P1 is not tested, for its ping or its
// IP, before P2 has a result, and once P2 works after failing, P1 is tested again by itself.
func TestH_MonitoringDetourTestedFirst(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond) // a 0 ms delay would read as "not measured"
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var dialer net.Dialer
	var m *OutboundMonitoring
	var p2Works, p1TooEarly atomic.Bool
	p2 := &fakeOutbound{tag: "p2", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		time.Sleep(200 * time.Millisecond) // slower than P1, which would otherwise be tested first
		if !p2Works.Load() {
			return nil, errors.New("p2: unreachable")
		}
		return dialer.DialContext(ctx, network, destination.String())
	}}
	p1 := &fakeOutbound{tag: "p1", deps: []string{"select"}, dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if !m.reg().outbounds["p2"].tested() {
			p1TooEarly.Store(true)
		}
		if !p2Works.Load() {
			return nil, errors.New("p1: its detour does not work")
		}
		return dialer.DialContext(ctx, network, destination.String())
	}}
	sel := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select", deps: []string{"p2"}}, all: []string{"p2"}}
	sel.selected = p2
	m = newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        4,
		URLs:           []string{server.URL + "/generate_204"},
		URLTestTimeout: badoption.Duration(time.Second),
	}, p2, p1, sel)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))

	delay := func(tag string) uint16 { return m.getUrlTest(tag).Delay }
	require.Eventually(t, func() bool { return delay("p1") != 0 }, 8*time.Second, 10*time.Millisecond)
	require.False(t, p1TooEarly.Load(), "p1 was tested before p2 had a result")
	require.Equal(t, TimeoutDelay, delay("p2"))
	require.Equal(t, TimeoutDelay, delay("p1"))

	p2Works.Store(true)
	require.NoError(t, m.TestNow("p2"))
	require.Eventually(t, func() bool {
		return delay("p1") > 0 && delay("p1") < TimeoutDelay
	}, 8*time.Second, 10*time.Millisecond, "p1 is tested again once p2 works")
	require.False(t, p1TooEarly.Load(), "p1 was tested while p2 was tested again")
}
