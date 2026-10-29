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
	"github.com/sagernet/sing-box/hiddify/ipinfo"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The IP information of the last run is shown at start, marked as from the cache, until it is
// looked up in this run: a failed test leaves it marked, and the next working test looks it up.
// A failed test used to clear the mark, so the old IP was never looked up again in that run.
func TestH_MonitoringIpInfoFromCacheUntilLookedUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond) // a 0 ms delay would read as "not measured"
		if r.URL.Path == "/ip" {
			w.Write([]byte(`{"ip":"203.0.113.9","country_code":"DE"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var dialer net.Dialer
	var working atomic.Bool
	out := &fakeOutbound{tag: "out", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if !working.Load() {
			return nil, errors.New("out: unreachable")
		}
		return dialer.DialContext(ctx, network, destination.String())
	}}
	options := option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{server.URL + "/generate_204"},
		IpInfoURL:      server.URL + "/ip",
		URLTestTimeout: badoption.Duration(time.Second),
	}
	cache := &fakeCache{data: map[string]*adapter.SavedBinary{}}
	previous := newTestMonitor(t, cache, options, out)
	require.NoError(t, htest.Start(previous, adapter.StartStateInitialize))
	setHistory(previous, "out", 77, false, &ipinfo.IpInfo{IP: "198.51.100.7", CountryCode: "NL"})
	require.NoError(t, previous.saveHistory())

	m := newTestMonitor(t, cache, options, out)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	his := m.getUrlTest("out")
	require.Equal(t, "198.51.100.7", his.IpInfo.IP, "the last run's IP is shown at start")
	require.True(t, his.IpInfoFromCache)
	m.workerWG.Add(1)
	go m.workerLoop()

	require.NoError(t, m.TestNow("out"))
	require.Eventually(t, func() bool { return m.getUrlTest("out").Delay == TimeoutDelay }, 3*time.Second, 10*time.Millisecond)
	his = m.getUrlTest("out")
	require.Equal(t, "198.51.100.7", his.IpInfo.IP, "a failed test keeps the last IP")
	require.True(t, his.IpInfoFromCache, "a failed test did not look it up")

	working.Store(true)
	require.NoError(t, m.TestNow("out"))
	require.Eventually(t, func() bool { return !m.getUrlTest("out").IpInfoFromCache }, 3*time.Second, 10*time.Millisecond, "a working test looks it up")
	his = m.getUrlTest("out")
	require.Equal(t, "203.0.113.9", his.IpInfo.IP)
	require.Equal(t, "DE", his.IpInfo.CountryCode)
}
