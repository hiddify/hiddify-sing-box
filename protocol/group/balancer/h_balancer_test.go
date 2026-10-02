package balancer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

type fakeOutboundManager struct {
	adapter.OutboundManager
	list []adapter.Outbound
}

func (m *fakeOutboundManager) Outbounds() []adapter.Outbound { return m.list }
func (m *fakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, o := range m.list {
		if o.Tag() == tag {
			return o, true
		}
	}
	return nil, false
}
func (m *fakeOutboundManager) Default() adapter.Outbound { return m.list[0] }

type fakeEndpointManager struct {
	adapter.EndpointManager
}

func (m *fakeEndpointManager) Endpoints() []adapter.Endpoint { return nil }

func newBalancerCtx(t *testing.T, o ...adapter.Outbound) (context.Context, *fakeOutboundManager) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.WithDefaultManager(ctx)
	manager := &fakeOutboundManager{list: o}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &fakeEndpointManager{})
	return ctx, manager
}

func TestH_BalancerConstruction(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("balancer")
	_, err := NewLoadBalance(context.Background(), nil, logger, "lb", option.BalancerOutboundOptions{})
	require.Error(t, err)

	a := newFake("a")
	ctx, _ := newBalancerCtx(t, a)
	out, err := NewLoadBalance(ctx, nil, logger, "lb", option.BalancerOutboundOptions{Outbounds: []string{"a"}, Strategy: "nope"})
	require.NoError(t, err)
	require.Error(t, out.(*Balancer).Start())

	out, err = NewLoadBalance(ctx, nil, logger, "lb", option.BalancerOutboundOptions{Outbounds: []string{"a", "missing"}, Strategy: StrategyRoundRobin})
	require.NoError(t, err)
	require.Error(t, out.(*Balancer).Start())

	for _, strategy := range []string{StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions, StrategyLowestDelay} {
		out, err = NewLoadBalance(ctx, nil, logger, "lb", option.BalancerOutboundOptions{Outbounds: []string{"a"}, Strategy: strategy, MaxRetry: 2})
		require.NoError(t, err)
		b := out.(*Balancer)
		require.Equal(t, "", b.Now())
		require.Nil(t, b.Selected(N.NetworkTCP))
		require.NoError(t, b.Start(), strategy)
		require.Equal(t, strategy, b.Strategy())
		require.Equal(t, C.TypeBalancer, b.Type())
		require.Equal(t, []string{"a"}, b.All())
		require.Equal(t, []string{"a"}, b.Dependencies())
		require.NoError(t, b.Close())
	}
}

func TestH_BalancerDialSetsRealOutbound(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	ctx, _ := newBalancerCtx(t, a, b)
	out, err := NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("balancer"), "lb", option.BalancerOutboundOptions{
		Outbounds: []string{"a", "b"},
		Strategy:  StrategyLowestDelay,
	})
	require.NoError(t, err)
	lb := out.(*Balancer)
	require.NoError(t, lb.Start())
	require.Equal(t, "a", lb.Now())
	require.Equal(t, a, lb.Selected(N.NetworkTCP))

	lb.strategyFn.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": his(300), "b": his(30)})
	metadata := &adapter.InboundContext{}
	conn, err := lb.DialContext(adapter.WithContext(ctx, metadata), N.NetworkTCP, M.ParseSocksaddrHostPort("example.com", 80))
	require.NoError(t, err)
	require.Equal(t, "b", metadata.GetRealOutbound())
	require.Equal(t, int32(1), b.dialed.Load())
	require.Equal(t, int32(0), a.dialed.Load())

	// interrupting the group closes tracked connections
	lb.interruptGroup.Interrupt(true)
	require.Eventually(t, func() bool {
		_, werr := conn.Write([]byte{1})
		return werr != nil
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, adapter.PreMatchContinue, lb.PreMatchFlow(N.NetworkTCP, netip.MustParseAddr("1.1.1.1")))
}

func TestH_BalancerFailoverViaMonitoring(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddr := M.ParseSocksaddr(server.Listener.Addr().String())

	var dialer net.Dialer
	healthy := func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination != serverAddr {
			return nil, errors.New("unreachable")
		}
		return dialer.DialContext(ctx, network, destination.String())
	}
	broken := func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return nil, errors.New("broken")
	}
	a, b := newFake("a"), newFake("b")
	a.dial = broken
	b.dial = healthy

	ctx, manager := newBalancerCtx(t, a, b)
	logger := log.NewNOPFactory().NewLogger("test")
	monitor, err := monitoring.NewOutboundMonitoring(ctx, logger, option.MonitoringOptions{
		URLs:           []string{server.URL + "/generate_204"},
		Workers:        2,
		DebounceWindow: badoption.Duration(20 * time.Millisecond),
		URLTestTimeout: badoption.Duration(2 * time.Second),
	})
	require.NoError(t, err)
	service.MustRegisterPtr(ctx, monitor)
	defer monitor.Close()

	out, err := NewLoadBalance(ctx, nil, logger, "lb", option.BalancerOutboundOptions{
		Outbounds: []string{"a", "b"},
		Strategy:  StrategyLowestDelay,
	})
	require.NoError(t, err)
	lb := out.(*Balancer)
	manager.list = append(manager.list, lb)

	require.NoError(t, monitor.Start(adapter.StartStateInitialize))
	require.NoError(t, lb.Start())
	require.Equal(t, "a", lb.Now())
	require.NoError(t, lb.PostStart())
	require.NoError(t, monitor.Start(adapter.StartStatePostStart))

	require.Eventually(t, func() bool { return lb.Now() == "b" }, 4*time.Second, 20*time.Millisecond)
	history := monitor.OutboundsHistory("lb")
	require.Equal(t, monitoring.TimeoutDelay, history["a"].Delay)
	require.Greater(t, history["b"].Delay, uint16(0))
	require.Less(t, history["b"].Delay, monitoring.TimeoutDelay)

	_, err = lb.DialContext(ctx, N.NetworkTCP, serverAddr)
	require.NoError(t, err)
}
