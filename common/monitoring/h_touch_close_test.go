package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/stretchr/testify/require"
)

// A Touch after Close (a URL test group touches on every dial) does not start the scheduler again:
// it did, outside the WaitGroup that Close waits on, and its Add could race that Wait.
func TestH_TouchAfterCloseStartsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &fakeOutboundManager{list: []adapter.Outbound{&fakeOutbound{tag: "a"}}})
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &fakeEndpointManager{})
	m, err := NewOutboundMonitoring(ctx, log.NewNOPFactory().NewLogger("monitoring"), option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        1,
		URLs:           []string{"http://127.0.0.1:9/generate_204"},
		URLTestTimeout: badoption.Duration(time.Second),
	})
	require.NoError(t, err)
	require.NoError(t, htest.StartAll(m))
	require.True(t, m.workersRunning.Load())

	require.NoError(t, m.Close())
	m.Touch()
	require.False(t, m.workersRunning.Load(), "Touch started the workers of a closed monitor")
}
