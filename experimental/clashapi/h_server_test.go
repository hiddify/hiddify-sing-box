package clashapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type hFakeOutbound struct {
	tag string
}

func (f *hFakeOutbound) Type() string           { return C.TypeDirect }
func (f *hFakeOutbound) Tag() string            { return f.tag }
func (f *hFakeOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (f *hFakeOutbound) Dependencies() []string { return nil }
func (f *hFakeOutbound) IsReady() bool          { return true }
func (f *hFakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unsupported")
}
func (f *hFakeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

type hFakeOutboundManager struct {
	adapter.OutboundManager
	direct adapter.Outbound
}

func (m *hFakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	if tag == m.direct.Tag() {
		return m.direct, true
	}
	return nil, false
}
func (m *hFakeOutboundManager) Default() adapter.Outbound { return m.direct }

type hFakeNetworkManager struct {
	adapter.NetworkManager
	resets atomic.Int32
}

func (m *hFakeNetworkManager) ResetNetwork(ctx context.Context) { m.resets.Add(1) }

type hFakeDNSRouter struct {
	adapter.DNSRouter
	cleared atomic.Int32
}

func (r *hFakeDNSRouter) ClearCache() { r.cleared.Add(1) }

type hTestEnv struct {
	server  *Server
	traffic *trafficontrol.Manager
	network *hFakeNetworkManager
	dns     *hFakeDNSRouter
	http    *httptest.Server
}

func newHTestEnv(t *testing.T, history *urltest.HistoryStorage) *hTestEnv {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = service.ContextWithDefaultRegistry(ctx)
	env := &hTestEnv{
		traffic: trafficontrol.NewManager(),
		network: &hFakeNetworkManager{},
		dns:     &hFakeDNSRouter{},
	}
	ctx = service.ContextWith[adapter.NetworkManager](ctx, env.network)
	ctx = service.ContextWith[adapter.DNSRouter](ctx, env.dns)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &hFakeOutboundManager{direct: &hFakeOutbound{tag: "direct"}})
	ctx = service.ContextWithPtr(ctx, env.traffic)
	if history != nil {
		ctx = service.ContextWithPtr(ctx, history)
	}
	logFactory := log.NewNOPFactory()
	ctx = service.ContextWithPtr(ctx, clashmode.NewManager(ctx, logFactory.NewLogger("mode"), "Rule", []string{"Rule", "Global", "Direct"}))
	srv, err := NewServer(ctx, logFactory, option.ClashAPIOptions{})
	require.NoError(t, err)
	env.server = srv.(*Server)
	env.http = httptest.NewServer(env.server.httpServer.Handler)
	t.Cleanup(env.http.Close)
	return env
}

func (e *hTestEnv) track(t *testing.T) (net.Conn, net.Conn) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c2.Close() })
	tracked := e.server.RoutedConnection(context.Background(), c1, adapter.InboundContext{
		Network:     N.NetworkTCP,
		Destination: M.ParseSocksaddrHostPort("1.2.3.4", 443),
	}, nil, nil)
	return tracked, c2
}

func hDo(t *testing.T, method, url string) *http.Response {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestH_ClashServerRequiresManagers(t *testing.T) {
	_, err := NewServer(service.ContextWithDefaultRegistry(context.Background()), log.NewNOPFactory(), option.ClashAPIOptions{})
	require.Error(t, err)
}

func TestH_ClashServerHistoryStorage(t *testing.T) {
	env := newHTestEnv(t, nil)
	require.NotNil(t, env.server.HistoryStorage(), "falls back to a private history storage")

	history := urltest.NewHistoryStorage()
	env = newHTestEnv(t, history)
	require.Same(t, history, env.server.HistoryStorage())
	require.Same(t, env.traffic, env.server.TrafficManager())
}

func TestH_ClashServerMode(t *testing.T) {
	env := newHTestEnv(t, nil)
	hook := observable.NewSubscriber[struct{}](4)
	env.server.SetModeUpdateHook(hook)
	updates, _ := hook.Subscription()

	require.Equal(t, "Rule", env.server.Mode())
	require.Equal(t, []string{"Rule", "Global", "Direct"}, env.server.ModeList())
	env.server.SetMode("global")
	require.Equal(t, "Global", env.server.Mode())
	require.Len(t, updates, 1)
	require.Equal(t, int32(1), env.dns.cleared.Load())
	env.server.SetMode("unknown")
	require.Equal(t, "Global", env.server.Mode())
}

func TestH_ClashServerRoutedTrackers(t *testing.T) {
	env := newHTestEnv(t, nil)
	tracked, _ := env.track(t)
	require.Equal(t, 1, env.traffic.ConnectionsLen())
	md := tracked.(*trafficontrol.TCPConn).Metadata()
	require.Equal(t, []string{"direct"}, md.Chain)

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	packet := env.server.RoutedPacketConnection(context.Background(), bufio.NewPacketConn(udp), adapter.InboundContext{Network: N.NetworkUDP}, nil, nil)
	require.Equal(t, 2, env.traffic.ConnectionsLen())
	require.NoError(t, packet.Close())
	require.NoError(t, tracked.Close())
	require.Equal(t, 0, env.traffic.ConnectionsLen())

	flow := env.server.RoutedFlow(context.Background(), adapter.InboundContext{}, nil, nil)
	require.NotNil(t, flow)
	flow.CountForward(1)
	flow.FlowEstablished()
}

func TestH_ClashAPIConnections(t *testing.T) {
	env := newHTestEnv(t, nil)
	first, peer := env.track(t)
	second, _ := env.track(t)
	firstID := first.(*trafficontrol.TCPConn).Metadata().ID

	resp := hDo(t, http.MethodGet, env.http.URL+"/connections")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var snapshot struct {
		Connections []struct {
			ID string `json:"id"`
		} `json:"connections"`
		UploadTotal *int64 `json:"uploadTotal"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&snapshot))
	require.Len(t, snapshot.Connections, 2)
	require.NotNil(t, snapshot.UploadTotal)

	resp = hDo(t, http.MethodDelete, env.http.URL+"/connections/"+uuid.Must(uuid.NewV4()).String())
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.Equal(t, 2, env.traffic.ConnectionsLen())

	resp = hDo(t, http.MethodDelete, env.http.URL+"/connections/"+firstID.String())
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.Equal(t, 1, env.traffic.ConnectionsLen())
	require.NotNil(t, env.traffic.Connection(second.(*trafficontrol.TCPConn).Metadata().ID))
	_, err := peer.Write([]byte{1})
	require.Error(t, err, "closed connection's pipe is torn down")

	resp = hDo(t, http.MethodDelete, env.http.URL+"/connections")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.Equal(t, 0, env.traffic.ConnectionsLen())
	require.Equal(t, int32(1), env.network.resets.Load())
}

func TestH_ClashServerClose(t *testing.T) {
	history := urltest.NewHistoryStorage()
	hook := observable.NewSubscriber[struct{}](1)
	history.SetHook(hook)
	env := newHTestEnv(t, history)
	require.NoError(t, env.server.Close())
	history.StoreURLTestHistory("x", &adapter.URLTestHistory{Delay: 1})
	updates, _ := hook.Subscription()
	require.Len(t, updates, 0, "server close also closes the history storage")
}
