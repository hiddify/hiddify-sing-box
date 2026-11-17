package monitoring

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// A cycle task whose outbound a hot reload removed before a worker reached it gives the cycle a
// failed outcome: it gave none, and the cycle waited for it for good, so no periodic test ran again.
func TestH_CycleEndsWhenAQueuedOutboundIsRemoved(t *testing.T) {
	release := make(chan struct{})
	blocking := func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, context.Canceled
	}
	a := &fakeOutbound{tag: "a", dial: blocking}
	b := &fakeOutbound{tag: "b", dial: blocking}
	manager := &fakeOutboundManager{list: []adapter.Outbound{a, b}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &fakeEndpointManager{})
	m, err := NewOutboundMonitoring(ctx, log.NewNOPFactory().NewLogger("monitoring"), option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{"http://127.0.0.1:9/generate_204"},
		URLTestTimeout: badoption.Duration(2 * time.Second),
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	m.workerWG.Add(1)
	go m.workerLoop() // one worker: the second task waits in the queue

	require.True(t, m.startCycleOnce())
	require.Eventually(t, func() bool { return len(m.normalQueue) == 1 }, 2*time.Second, 5*time.Millisecond, "one task runs, one waits")

	// which one waits in the queue is the one the reload removes
	waiting := "b"
	sa := m.reg().outbounds["a"]
	sa.mu.Lock()
	if !sa.testing {
		waiting = "a"
	}
	sa.mu.Unlock()
	if waiting == "a" {
		manager.list = []adapter.Outbound{b}
	} else {
		manager.list = []adapter.Outbound{a}
	}
	require.NoError(t, m.Reload())
	close(release)

	ended := func() bool { return !m.cycleRunning.Load() }
	if !hEventually(ended, 15*time.Second) {
		t.Fatalf("the cycle never ended after outbound %q was removed while its task was queued (cycleRunning stays true)", waiting)
	}
}

func hEventually(cond func() bool, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}
