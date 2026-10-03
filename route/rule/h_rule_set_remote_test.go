package rule

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
)

func hRunLoopUpdate(t *testing.T, ruleSet *RemoteRuleSet, cancel context.CancelFunc, wait time.Duration) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		ruleSet.loopUpdate()
	}()
	time.Sleep(wait)
	cancel()
	select {
	case r := <-done:
		require.Nil(t, r, fmt.Sprint("loopUpdate panicked: ", r))
	case <-time.After(3 * time.Second):
		t.Fatal("loopUpdate did not exit after context cancel")
	}
}

func TestH_RemoteRuleSetLoopUpdateExitsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	ruleSet := &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger.NOP(),
		tag:            "remote",
		updateInterval: time.Hour,
		lastUpdated:    time.Now(),
		updateTicker:   time.NewTicker(time.Hour),
	}
	defer ruleSet.Close()
	hRunLoopUpdate(t, ruleSet, cancel, 50*time.Millisecond)
}

func TestH_RemoteRuleSetLoopUpdateFetchesWhenStale(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":["example.org"]}]}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ruleSet := &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger.NOP(),
		tag:            "remote",
		url:            server.URL,
		options:        option.RuleSet{Format: C.RuleSetFormatSource},
		httpClient:     server.Client(),
		updateInterval: time.Hour,
		lastUpdated:    time.Now().Add(-2 * time.Hour),
		updateTicker:   time.NewTicker(time.Hour),
		callbacks:      list.List[adapter.RuleSetUpdateCallback]{},
	}
	ruleSet.refs.Store(1)
	defer ruleSet.Close()
	hRunLoopUpdate(t, ruleSet, cancel, 300*time.Millisecond)
	require.Equal(t, int32(1), hits.Load())
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.org"}))
}

func TestH_RemoteRuleSetLoopUpdateNeverUpdated(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ruleSet := &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger.NOP(),
		tag:            "remote",
		url:            server.URL,
		options:        option.RuleSet{Format: C.RuleSetFormatSource},
		httpClient:     server.Client(),
		updateInterval: time.Hour,
		updateTicker:   time.NewTicker(time.Hour),
	}
	defer ruleSet.Close()
	hRunLoopUpdate(t, ruleSet, cancel, 200*time.Millisecond)
}

func TestH_RemoteRuleSetRetriesFailedFetchUntilSuccess(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	ruleSet := &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger.NOP(),
		tag:            "remote",
		url:            server.URL,
		options:        option.RuleSet{Format: C.RuleSetFormatSource},
		httpClient:     server.Client(),
		updateInterval: time.Hour,
		updateTicker:   time.NewTicker(time.Hour),
		fetchFailed:    true,
		retryDelays:    []time.Duration{10 * time.Millisecond, 20 * time.Millisecond},
	}
	ruleSet.refs.Store(1)
	defer ruleSet.Close()
	hRunLoopUpdate(t, ruleSet, cancel, 300*time.Millisecond)
	require.Equal(t, int32(4), hits.Load(), "should retry until the fetch succeeds, then stop")
	require.False(t, ruleSet.lastUpdated.IsZero())
	require.False(t, ruleSet.fetchFailed)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.org"}))
}

func TestH_RemoteRuleSetKeepsCachedRulesOnFailedRefresh(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ruleSet := &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger.NOP(),
		tag:            "remote",
		url:            server.URL,
		options:        option.RuleSet{Format: C.RuleSetFormatSource},
		httpClient:     server.Client(),
		updateInterval: time.Hour,
		lastUpdated:    time.Now().Add(-2 * time.Hour),
		updateTicker:   time.NewTicker(time.Hour),
		retryDelays:    []time.Duration{10 * time.Millisecond},
	}
	ruleSet.refs.Store(1)
	require.NoError(t, ruleSet.loadBytes([]byte(`{"version":4,"rules":[{"domain":["cached.example"]}]}`)))
	defer ruleSet.Close()
	hRunLoopUpdate(t, ruleSet, cancel, 200*time.Millisecond)
	require.Greater(t, hits.Load(), int32(2), "failed refresh should be retried")
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "cached.example"}), "cached rules must stay in use")
}
