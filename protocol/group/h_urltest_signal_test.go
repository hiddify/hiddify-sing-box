package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

type hListedOutboundManager struct {
	hOutboundManager
	list []adapter.Outbound
}

func (m *hListedOutboundManager) Outbounds() []adapter.Outbound { return m.list }

type hNoEndpoints struct{ adapter.EndpointManager }

func (hNoEndpoints) Endpoints() []adapter.Endpoint { return nil }

// A URL test that moves to another member tells monitoring at once, as a selector does: what
// follows the group (a tunnel through it) must not wait for the next monitoring test.
func TestH_URLTestSignalsItsMove(t *testing.T) {
	server := hProbeServer(t)
	fast, slow := hProbe(t, server, "fast", 5*time.Millisecond), hProbe(t, server, "slow", 60*time.Millisecond)
	manager := &hListedOutboundManager{hOutboundManager: hOutboundManager{outbounds: map[string]adapter.Outbound{"fast": fast, "slow": slow}}}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWithPtr(ctx, urltest.NewHistoryStorage())
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, hNoEndpoints{})
	logger := log.NewNOPFactory().NewLogger("test")
	monitor, err := monitoring.NewOutboundMonitoring(ctx, logger, option.MonitoringOptions{})
	require.NoError(t, err)
	service.MustRegisterPtr(ctx, monitor)
	defer monitor.Close()

	created, err := NewURLTest(ctx, nil, logger, "auto", option.URLTestOutboundOptions{Outbounds: []string{"fast", "slow"}, URL: "http://probe.test/generate_204"})
	require.NoError(t, err)
	group := created.(*URLTest)
	group.outbound = manager
	manager.outbounds["auto"] = group
	manager.list = []adapter.Outbound{fast, slow, group}
	require.NoError(t, group.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { group.group.Close() })
	require.NoError(t, htest.Start(monitor, adapter.StartStateInitialize)) // no test cycles: only signals publish

	_, err = group.URLTest(context.Background())
	require.NoError(t, err)
	require.Equal(t, "fast", hSelected(group))
	events, err := monitor.SubscribeGroup("")
	require.NoError(t, err)
	defer monitor.UnsubscribeGroup("", events)

	fast.dead.Store(true)
	_, err = group.URLTest(context.Background())
	require.NoError(t, err)
	require.Equal(t, "slow", hSelected(group))
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("the move was not signalled")
	}
}
