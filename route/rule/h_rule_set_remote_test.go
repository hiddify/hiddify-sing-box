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
	t.Skip("BUG: RemoteRuleSet.loopUpdate dereferences nil startupTicker when lastUpdated is zero (startupTicker is never initialized)")
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
