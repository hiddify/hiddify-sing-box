package warp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sagernet/sing-box/adapter/htest"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type hRecordingDialer struct {
	access  sync.Mutex
	targets []M.Socksaddr
}

func (d *hRecordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.targets = append(d.targets, destination)
	d.access.Unlock()
	return nil, errors.New("detour refused")
}

func (d *hRecordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func (d *hRecordingDialer) count() int {
	d.access.Lock()
	defer d.access.Unlock()
	return len(d.targets)
}

type hFakeOutbound struct {
	adapter.Outbound
	*hRecordingDialer
	tag string
}

func (o *hFakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.hRecordingDialer.DialContext(ctx, network, destination)
}

func (o *hFakeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return o.hRecordingDialer.ListenPacket(ctx, destination)
}

type hFakeOutboundManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
}

func (m *hFakeOutboundManager) Outbounds() []adapter.Outbound {
	return m.outbounds
}

func (m *hFakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, outbound := range m.outbounds {
		if outbound.(*hFakeOutbound).tag == tag {
			return outbound, true
		}
	}
	return nil, false
}

type hFakeCacheFile struct {
	adapter.CacheFile
	access sync.Mutex
	store  map[string]*adapter.SavedBinary
	loads  []string
	saves  []string
}

func (c *hFakeCacheFile) StoreWARPConfig() bool { return true }

func (c *hFakeCacheFile) LoadBinary(tag string) *adapter.SavedBinary {
	c.access.Lock()
	defer c.access.Unlock()
	c.loads = append(c.loads, tag)
	return c.store[tag]
}

func (c *hFakeCacheFile) SaveBinary(tag string, binary *adapter.SavedBinary) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.saves = append(c.saves, tag)
	c.store[tag] = binary
	return nil
}

func hTestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// hShortContext ends the retries of a start that cannot work soon.
func hShortContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func hLogger() log.ContextLogger {
	return log.NewNOPFactory().NewLogger("warp-test")
}

const hWARPConfigJSON = `{
	"private_key": "GAl2z55U2UzNU5FG+LW3kowK+BA/WGMi1dWYwx20pWk=",
	"interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36::1"}},
	"peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "endpoint": {"host": "engage.cloudflareclient.com:2408", "ports": [2408]}}]
}`

func hWARPConfig(t *testing.T, content string) *C.WARPConfig {
	var config C.WARPConfig
	require.NoError(t, json.Unmarshal([]byte(content), &config))
	return &config
}

func TestH_GetWarpProfileDialerExistingProfileUsesDetour(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	detour := &hRecordingDialer{}
	_, err = GetWarpProfileDialer(hTestContext(t), detour, &option.WARPProfile{AuthToken: "tok", ID: "id", PrivateKey: key.String()})
	require.ErrorContains(t, err, "detour refused")
	require.NotZero(t, detour.count())
	require.Equal(t, M.ParseSocksaddr("api.cloudflareclient.com:443"), detour.targets[0])
}

func TestH_GetWarpProfileDialerRegistersNewProfile(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	detour := &hRecordingDialer{}
	_, err = GetWarpProfileDialer(hTestContext(t), detour, &option.WARPProfile{PrivateKey: key.String(), ID: "id-without-token"})
	require.ErrorContains(t, err, "detour refused")
	require.NotZero(t, detour.count())

	detour = &hRecordingDialer{}
	_, err = GetWarpProfileDialer(hTestContext(t), detour, &option.WARPProfile{PrivateKey: "not-a-key"})
	require.Error(t, err)
	require.Zero(t, detour.count(), "invalid key must fail before any request")
}

func TestH_GetWarpProfileDetourNotFound(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](hTestContext(t), &hFakeOutboundManager{})
	_, err := GetWarpProfile(ctx, &option.WARPProfile{Detour: "missing"})
	require.ErrorContains(t, err, "outbound detour not found: missing")
}

func TestH_GetWarpProfileFallsBackToAllOutbounds(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	first := &hFakeOutbound{hRecordingDialer: &hRecordingDialer{}, tag: "first"}
	second := &hFakeOutbound{hRecordingDialer: &hRecordingDialer{}, tag: "second"}
	ctx := service.ContextWith[adapter.OutboundManager](hTestContext(t), &hFakeOutboundManager{outbounds: []adapter.Outbound{first, second}})
	profile, err := GetWarpProfile(ctx, &option.WARPProfile{PrivateKey: key.String(), Detour: "first"})
	require.Error(t, err)
	require.Nil(t, profile)
	require.GreaterOrEqual(t, first.count(), 2, "detour is tried first, then again in the fallback loop")
	require.NotZero(t, second.count())
}

func TestH_GetWarpProfileWithoutOutboundManagerReturnsError(t *testing.T) {
	profile, err := GetWarpProfile(hTestContext(t), &option.WARPProfile{PrivateKey: "not-a-key"})
	require.Error(t, err)
	require.Nil(t, profile)
}

func hNewWARP(t *testing.T, ctx context.Context, options option.WARPEndpointOptions) *WARPEndpoint {
	ep, err := NewWARPEndpoint(ctx, nil, hLogger(), "warp-tag", options)
	require.NoError(t, err)
	return ep.(*WARPEndpoint)
}

func TestH_NewWARPEndpointMetadata(t *testing.T) {
	options := option.WARPEndpointOptions{Profile: option.WARPProfile{Detour: "profile-out"}}
	options.Detour = "wg-out"
	ep := hNewWARP(t, hTestContext(t), options)
	require.Equal(t, C.TypeWARP, ep.Type())
	require.Equal(t, "warp-tag", ep.Tag())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, ep.Network())
	require.Equal(t, []string{"wg-out", "profile-out"}, ep.Dependencies())
	require.NoError(t, htest.Start(ep, adapter.StartStateStart))
	require.True(t, ep.mtx.TryLock(), "mtx must stay free so dials during start do not block")
	ep.mtx.Unlock()
	require.False(t, adapter.IsReady(ep), "inner endpoint is not installed before PostStart")
}

func TestH_WARPStartFailureLeavesEndpointUninitialized(t *testing.T) {
	options := option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON)}
	options.Detour = "missing-detour"
	ep := hNewWARP(t, hShortContext(t), options)
	ep.startHandler()

	require.False(t, adapter.IsReady(ep))
	hRequireConnecting(t, "WARP · WG", adapter.DisplayType(ep))
	_, err := ep.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
	require.ErrorContains(t, err, "endpoint not initialized")
	_, err = ep.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "endpoint not initialized")
	require.NoError(t, ep.Close())
}

func TestH_WARPStartPostStartRunsHandler(t *testing.T) {
	options := option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON), AWG: &option.AwgOptions{Jc: 3}}
	options.Detour = "missing-detour"
	ep := hNewWARP(t, hTestContext(t), options)
	require.NoError(t, htest.Start(ep, adapter.StartStatePostStart))
	done := make(chan bool, 1)
	go func() { done <- adapter.IsReady(ep) }()
	select {
	case ready := <-done:
		require.False(t, ready)
	case <-time.After(3 * time.Second):
		t.Fatal("start handler did not release the endpoint")
	}
}

func TestH_WARPUsesCachedConfig(t *testing.T) {
	cached, err := json.Marshal(hWARPConfig(t, hWARPConfigJSON))
	require.NoError(t, err)
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{"unique": {Content: cached}}}
	ctx := service.ContextWith[adapter.CacheFile](hShortContext(t), cache)
	options := option.WARPEndpointOptions{UniqueIdentifier: "unique"}
	options.Detour = "missing-detour"
	hNewWARP(t, ctx, options).startHandler()
	require.Equal(t, []string{"unique"}, cache.loads)
	require.Empty(t, cache.saves)

	cache = &hFakeCacheFile{store: map[string]*adapter.SavedBinary{"warp-tag": {Content: cached}}}
	ctx = service.ContextWith[adapter.CacheFile](hShortContext(t), cache)
	options = option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON), Profile: option.WARPProfile{Recreate: true}}
	options.Detour = "missing-detour"
	hNewWARP(t, ctx, options).startHandler()
	require.Empty(t, cache.loads, "recreate must bypass the cache")
	require.Empty(t, cache.saves)
}

func TestH_WARPMalformedCachedConfig(t *testing.T) {
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{"warp-tag": {Content: []byte("{not json")}}}
	ctx := service.ContextWith[adapter.CacheFile](hShortContext(t), cache)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &hFakeOutboundManager{})
	// a broken saved profile is replaced by a new one; the detour keeps the test off the network
	ep := hNewWARP(t, ctx, option.WARPEndpointOptions{Profile: option.WARPProfile{Detour: "missing"}})
	ep.startHandler()
	require.Equal(t, []string{"warp-tag"}, cache.loads)
	require.Equal(t, adapter.StatusConnecting, ep.Status(), "registering ended with the context, not failed")
	_, err := ep.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
	require.ErrorContains(t, err, "endpoint not initialized")
}

func TestH_WARPConfigWithoutPortsDoesNotPanic(t *testing.T) {
	options := option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, `{"private_key":"x","peers":[{"endpoint":{"host":"h:1"}}]}`)}
	options.Detour = "missing-detour"
	options.ServerPort = 2408
	ep := hNewWARP(t, hShortContext(t), options)
	require.NotPanics(t, ep.startHandler)
}

func TestH_WARPConfigWithoutPeersDoesNotPanic(t *testing.T) {
	options := option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, `{"private_key":"x","peers":[]}`)}
	options.Detour = "missing-detour"
	ep := hNewWARP(t, hTestContext(t), options)
	require.NotPanics(t, ep.startHandler)
	require.False(t, adapter.IsReady(ep))
}

func TestH_WARPPeerEndpoint(t *testing.T) {
	config := hWARPConfig(t, `{"private_key":"x","peers":[{"endpoint":{"host":"engage.cloudflareclient.com:2408","ports":[500,4500]}}]}`)
	address, port, err := warpPeerEndpoint(config, option.ServerOptions{})
	require.NoError(t, err)
	require.Equal(t, "engage.cloudflareclient.com", address)
	require.Contains(t, []uint16{500, 4500}, port)
	address, port, err = warpPeerEndpoint(config, option.ServerOptions{Server: "162.159.192.1", ServerPort: 854})
	require.NoError(t, err)
	require.Equal(t, "162.159.192.1", address)
	require.Equal(t, uint16(854), port)
	// no ports listed: the port in the host is used
	address, port, err = warpPeerEndpoint(hWARPConfig(t, `{"private_key":"x","peers":[{"endpoint":{"host":"h:1701"}}]}`), option.ServerOptions{})
	require.NoError(t, err)
	require.Equal(t, "h", address)
	require.Equal(t, uint16(1701), port)
	_, _, err = warpPeerEndpoint(hWARPConfig(t, `{"private_key":"x","peers":[{"endpoint":{"host":"h"}}]}`), option.ServerOptions{})
	require.Error(t, err)
	_, _, err = warpPeerEndpoint(hWARPConfig(t, `{"private_key":"x","peers":[]}`), option.ServerOptions{})
	require.Error(t, err)
}

func TestH_RegisterWARPEndpoint(t *testing.T) {
	registry := endpoint.NewRegistry()
	RegisterWARPEndpoint(registry)
	options, loaded := registry.CreateOptions(C.TypeWARP)
	require.True(t, loaded)
	require.IsType(t, &option.WARPEndpointOptions{}, options)
}

// a profile whose host is a domain uses its own IPv4 address, so WireGuard does not send to
// both families over one detour association
func TestH_WarpPeerEndpointProfileAddress(t *testing.T) {
	config := hWARPConfig(t, `{"private_key":"x","peers":[{"endpoint":{"host":"engage.cloudflareclient.com:2408","v4":"162.159.192.1:0","v6":"[2606:4700:d0::a29f:c001]:0"}}]}`)
	address, port, err := warpPeerEndpoint(config, option.ServerOptions{})
	require.NoError(t, err)
	require.Equal(t, "162.159.192.1", address)
	require.EqualValues(t, 2408, port)

	config = hWARPConfig(t, `{"private_key":"x","peers":[{"endpoint":{"host":"engage.cloudflareclient.com:2408","v6":"[2606:4700:d0::a29f:c001]:0"}}]}`)
	address, _, err = warpPeerEndpoint(config, option.ServerOptions{})
	require.NoError(t, err)
	require.Equal(t, "2606:4700:d0::a29f:c001", address)

	address, _, err = warpPeerEndpoint(config, option.ServerOptions{Server: "engage.cloudflareclient.com"})
	require.NoError(t, err)
	require.Equal(t, "engage.cloudflareclient.com", address, "a server set in the config is kept")
}

func TestH_WARPMASQUEAndAWGConflict(t *testing.T) {
	_, err := NewWARPEndpoint(hTestContext(t), nil, hLogger(), "warp-tag", option.WARPEndpointOptions{
		MASQUE: &option.WARPMASQUEOptions{Enabled: true},
		AWG:    &option.AwgOptions{Jc: 4},
	})
	require.ErrorContains(t, err, "masque and awg")
}

func TestH_WARPDisplayTypeByTunnel(t *testing.T) {
	hRequireConnecting(t, "WARP · WG", adapter.DisplayType(hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{})))
	hRequireConnecting(t, "WARP · AWG", adapter.DisplayType(hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{AWG: &option.AwgOptions{Jc: 4}})))
	hRequireConnecting(t, "WARP · MASQUE", adapter.DisplayType(hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{MASQUE: &option.WARPMASQUEOptions{Enabled: true}})))
	hRequireConnecting(t, "WARP · MASQUE", adapter.DisplayType(hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{MASQUE: &option.WARPMASQUEOptions{VHTTP: "h2"}})), "any setting turns it on")
	hRequireConnecting(t, "WARP · WG", adapter.DisplayType(hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{MASQUE: &option.WARPMASQUEOptions{}})), "an empty block is not MASQUE")
}

// The box closes the endpoint's scope, not the endpoint: its background work (port rotation,
// failover, following the detour) must stop with the scope, or it outlives the box.
func TestH_WARPStopsWithItsScope(t *testing.T) {
	ep := hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{})
	scope := adapter.NewScope(context.Background(), hLogger())
	require.NoError(t, ep.Start(adapter.StartStateInitialize, scope))
	select {
	case <-ep.done:
		t.Fatal("stopped before the scope closed")
	default:
	}
	require.NoError(t, scope.Close())
	select {
	case <-ep.done:
	case <-time.After(time.Second):
		t.Fatal("background work outlives the closed scope")
	}
}

func hRequireConnecting(t *testing.T, base string, display string, message ...any) {
	t.Helper()
	gotBase, mark := adapter.SplitStatus(display)
	require.Equal(t, base, gotBase, message...)
	require.NotEmpty(t, mark, message...)
}

// While the device is registered, WARP shows as registering; a config it cannot use is failed.
func TestH_WARPStatusRegisteringAndFailed(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](hTestContext(t), &hFakeOutboundManager{})
	ep := hNewWARP(t, ctx, option.WARPEndpointOptions{Profile: option.WARPProfile{Detour: "missing"}})
	require.Equal(t, adapter.StatusConnecting, ep.Status(), "not started")
	go ep.startHandler()
	require.Eventually(t, func() bool { return ep.Status() == adapter.StatusRegistering }, 2*time.Second, 10*time.Millisecond)
	ep.Close()

	broken := hNewWARP(t, hShortContext(t), option.WARPEndpointOptions{WARPConfig: &C.WARPConfig{PrivateKey: "key"}})
	broken.startHandler()
	require.Equal(t, adapter.StatusFailed, broken.Status(), "a config without peers cannot work")
	_, mark := adapter.SplitStatus(adapter.DisplayType(broken))
	require.Equal(t, "❌ Failed", mark)
}
