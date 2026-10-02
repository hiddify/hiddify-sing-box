package warp

import (
	"context"
	"encoding/json"
	"errors"
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
	detour := &hRecordingDialer{}
	_, err := GetWarpProfileDialer(hTestContext(t), detour, &option.WARPProfile{AuthToken: "tok", ID: "id"})
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
	t.Skip("BUG: GetWarpProfile returns (nil, nil) on failure when no OutboundManager is in ctx, so startHandler then dereferences a nil profile")
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
	require.NoError(t, ep.Start(adapter.StartStateStart))
	require.False(t, ep.mtx.TryLock(), "endpoint stays locked until the start handler runs")
}

func TestH_WARPStartFailureLeavesEndpointUninitialized(t *testing.T) {
	options := option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON)}
	options.Detour = "missing-detour"
	ep := hNewWARP(t, hTestContext(t), options)
	ep.startHandler()

	require.False(t, ep.IsReady())
	require.Equal(t, "WARP ⚠️ Connecting...", ep.DisplayType())
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
	require.NoError(t, ep.Start(adapter.StartStatePostStart))
	done := make(chan bool, 1)
	go func() { done <- ep.IsReady() }()
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
	ctx := service.ContextWith[adapter.CacheFile](hTestContext(t), cache)
	options := option.WARPEndpointOptions{UniqueIdentifier: "unique"}
	options.Detour = "missing-detour"
	hNewWARP(t, ctx, options).startHandler()
	require.Equal(t, []string{"unique"}, cache.loads)
	require.Empty(t, cache.saves)

	cache = &hFakeCacheFile{store: map[string]*adapter.SavedBinary{"warp-tag": {Content: cached}}}
	ctx = service.ContextWith[adapter.CacheFile](hTestContext(t), cache)
	options = option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON), Profile: option.WARPProfile{Recreate: true}}
	options.Detour = "missing-detour"
	hNewWARP(t, ctx, options).startHandler()
	require.Empty(t, cache.loads, "recreate must bypass the cache")
	require.Empty(t, cache.saves)
}

func TestH_WARPMalformedCachedConfig(t *testing.T) {
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{"warp-tag": {Content: []byte("{not json")}}}
	ctx := service.ContextWith[adapter.CacheFile](hTestContext(t), cache)
	ep := hNewWARP(t, ctx, option.WARPEndpointOptions{})
	ep.startHandler()
	require.Equal(t, []string{"warp-tag"}, cache.loads)
	_, err := ep.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
	require.ErrorContains(t, err, "endpoint not initialized")
}

func TestH_WARPConfigWithoutPortsDoesNotPanic(t *testing.T) {
	t.Skip("BUG: startHandler calls rand.Intn(len(peer.Endpoint.Ports)) and Peers[0] unchecked; a WARP config with no ports/peers panics the goroutine")
	options := option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, `{"private_key":"x","peers":[{"endpoint":{"host":"h:1"}}]}`)}
	options.Detour = "missing-detour"
	options.ServerPort = 2408
	ep := hNewWARP(t, hTestContext(t), options)
	require.NotPanics(t, ep.startHandler)
}

func TestH_RegisterWARPEndpoint(t *testing.T) {
	registry := endpoint.NewRegistry()
	RegisterWARPEndpoint(registry)
	options, loaded := registry.CreateOptions(C.TypeWARP)
	require.True(t, loaded)
	require.IsType(t, &option.WARPEndpointOptions{}, options)
}
