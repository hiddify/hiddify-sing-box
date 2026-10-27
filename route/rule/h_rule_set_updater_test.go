package rule

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func hUpdaterRuleSet(t *testing.T, url string, lastUpdated time.Time, retryDelays ...time.Duration) *RemoteRuleSet {
	ctx, cancel := context.WithCancel(context.Background())
	ruleSet := &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger.NOP(),
		tag:            "remote",
		url:            url,
		options:        option.RuleSet{Format: C.RuleSetFormatSource},
		httpClient:     http.DefaultClient,
		updateInterval: time.Hour,
		lastUpdated:    lastUpdated,
		retryDelays:    retryDelays,
	}
	ruleSet.refs.Store(1)
	t.Cleanup(func() { ruleSet.Close() })
	return ruleSet
}

// hRunUpdater runs the updater for wait and returns whether a download was loaded; the channel
// orders the test's reads after the updater's writes.
func hRunUpdater(t *testing.T, ruleSet *RemoteRuleSet, wait time.Duration) bool {
	loaded := make(chan struct{}, 16)
	ruleSet.RegisterCallback(func(adapter.RuleSet) { loaded <- struct{}{} })
	updater := NewRuleSetUpdater(context.Background(), []adapter.RuleSet{ruleSet})
	updater.Start()
	defer updater.Close()
	select {
	case <-loaded:
		time.Sleep(wait / 4) // no more fetches after a success
		return true
	case <-time.After(wait):
		return false
	}
}

// A rule set that has never been downloaded is fetched at once, and a failed fetch is retried with
// backoff instead of after update_interval.
func TestH_RuleSetUpdaterRetriesFailedFetch(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":["example.org"]}]}`))
	}))
	defer server.Close()
	ruleSet := hUpdaterRuleSet(t, server.URL, time.Time{}, 10*time.Millisecond, 20*time.Millisecond)
	require.True(t, hRunUpdater(t, ruleSet, 2*time.Second), "retried until the fetch succeeded")
	require.EqualValues(t, 4, hits.Load(), "no fetch after the success")
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.org"}))
}

// A failed refresh keeps the cached rules in use while it retries.
func TestH_RuleSetUpdaterKeepsCachedRules(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ruleSet := hUpdaterRuleSet(t, server.URL, time.Now().Add(-2*time.Hour), 10*time.Millisecond)
	require.NoError(t, ruleSet.loadBytes([]byte(`{"version":4,"rules":[{"domain":["cached.example"]}]}`)))
	require.False(t, hRunUpdater(t, ruleSet, 200*time.Millisecond))
	require.Greater(t, hits.Load(), int32(2))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "cached.example"}))
}

// A fresh rule set is not fetched before update_interval.
func TestH_RuleSetUpdaterWaitsForInterval(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer server.Close()
	ruleSet := hUpdaterRuleSet(t, server.URL, time.Now())
	require.False(t, hRunUpdater(t, ruleSet, 100*time.Millisecond))
	require.Zero(t, hits.Load())
}
