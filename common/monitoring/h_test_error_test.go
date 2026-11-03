package monitoring

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// A failed URL test keeps its error in the history, for the app to say why the proxy failed; the
// next test that works clears it.
func TestH_MonitoringKeepsTheErrorOfAFailedTest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	proxy := &fakeOutbound{tag: "proxy", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return nil, errors.New("handshake refused by the server")
	}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{server.URL + "/generate_204"},
		URLTestTimeout: badoption.Duration(time.Second),
	}, proxy)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	m.workerWG.Add(1)
	go m.workerLoop()

	history := func() adapter.URLTestHistory {
		state := m.reg().outbounds["proxy"]
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history
	}
	require.NoError(t, m.TestNow("proxy"))
	// a staged test shows a miss before it settles; the error comes with the result
	require.Eventually(t, func() bool { return history().Error != "" }, 10*time.Second, 10*time.Millisecond)
	require.Equal(t, TimeoutDelay, history().Delay)
	require.Contains(t, history().Error, "handshake refused by the server")
	require.Contains(t, m.history.LoadURLTestHistory("proxy").Error, "handshake refused by the server",
		"the stored history, which the app reads, has it too")

	// a test that works clears it: the delay it shows first, before the IP lookup, and its result
	state := m.reg().outbounds["proxy"]
	m.applyInterim(&testTask{outboundTag: "proxy"}, state, adapter.URLTestHistory{Time: time.Now(), Delay: 42}, false)
	require.Empty(t, history().Error, "the delay of a test that answered")
	m.applyResult(testOutcome{outboundTag: "proxy", history: adapter.URLTestHistory{Time: time.Now(), Delay: TimeoutDelay}, err: E.New("refused again")})
	require.Equal(t, "refused again", history().Error)
	m.applyInterim(&testTask{outboundTag: "proxy"}, state, adapter.URLTestHistory{Time: time.Now(), Delay: TimeoutDelay}, true)
	require.Equal(t, "refused again", history().Error, "a tentative miss keeps it")
	m.applyResult(testOutcome{outboundTag: "proxy", history: adapter.URLTestHistory{Time: time.Now(), Delay: 42}})
	require.Empty(t, history().Error, "the result of a test that worked")
}
