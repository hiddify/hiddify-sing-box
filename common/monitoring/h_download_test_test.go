package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// downloadTestMonitor is a monitor of one outbound "proxy" whose URL test answers, and whose
// download test gets the whole body, or the first 16 KiB and then nothing when frozen, or no
// answer at all when silent.
func downloadTestMonitor(t *testing.T, frozen, silent bool) *OutboundMonitoring {
	const size = 64 << 10
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if silent {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if !frozen {
			_, _ = w.Write(make([]byte, size))
			return
		}
		_, _ = w.Write(make([]byte, 16<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	// a dial of 2ms: a staged test takes a 0 ms delay for no answer
	wait := func(context.Context) error { time.Sleep(2 * time.Millisecond); return nil }
	proxy := &fakeOutbound{tag: "proxy", dial: dialTo(M.ParseSocksaddr(server.Listener.Addr().String()), wait)}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:         badoption.Duration(time.Hour),
		URLs:             []string{server.URL + "/generate_204"},
		URLTestTimeout:   badoption.Duration(300 * time.Millisecond),
		OnDemandTimeouts: badoption.Listable[badoption.Duration]{badoption.Duration(time.Second), badoption.Duration(2 * time.Second)},
		DownloadTestURL:  server.URL + "/__down",
	}, proxy)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	setHistory(m, "proxy", 0, false, &ipinfo.IpInfo{}) // known IP: no lookup after the tests
	return m
}

// An outbound whose connections freeze after their first kilobytes passes the URL test, which
// moves a few bytes, and fails the download test, in a cycle and when asked for; it never shows
// as working on the way.
func TestH_MonitoringDownloadTestFailsAFrozenOutbound(t *testing.T) {
	for _, frozen := range []bool{false, true} {
		for _, staged := range []bool{false, true} {
			t.Run("frozen "+strconv.FormatBool(frozen)+" staged "+strconv.FormatBool(staged), func(t *testing.T) {
				m := downloadTestMonitor(t, frozen, false)
				var shown []uint16
				interim := func(his adapter.URLTestHistory, tentative bool) {
					if !tentative {
						shown = append(shown, his.Delay)
					}
				}
				history, err := m.tester(context.Background(), "proxy", interim, staged, false)
				if !frozen {
					require.NoError(t, err)
					require.Less(t, history.Delay, TimeoutDelay)
					require.Len(t, shown, 1, "the delay shows once both tests passed")
					return
				}
				require.ErrorContains(t, err, "download stalled after 16384 bytes")
				require.True(t, isDownloadTestError(err), "its URL test answered: the cycle keeps its test URL")
				require.Equal(t, TimeoutDelay, history.Delay)
				require.Empty(t, shown, "a frozen outbound never shows a delay")
			})
		}
	}
}

// A download server that sends no body (unreachable from the exit, down) tells nothing of the
// outbound: its URL test result stands.
func TestH_MonitoringDownloadTestWithoutABodyTellsNothing(t *testing.T) {
	m := downloadTestMonitor(t, false, true)
	history, err := m.tester(context.Background(), "proxy", nil, false, false)
	require.NoError(t, err)
	require.Less(t, history.Delay, TimeoutDelay)
}
