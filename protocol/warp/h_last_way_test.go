package warp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The endpoint and noise that worked are kept as the tunnel's last way, and the next start takes
// them after one check, without naming the network or scanning; a way that does not answer
// leaves the start to search.
func TestH_WARPLastWay(t *testing.T) {
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{}}
	ep := hNewWARP(t, service.ContextWith[adapter.CacheFile](hTestContext(t), cache), option.WARPEndpointOptions{
		WARPConfig: hWARPConfig(t, hWARPConfigJSON),
		Scanner:    &option.WARPScannerOptions{Enabled: true, SearchNoise: true},
	})
	_, found := ep.lastWay(modeWireGuard)
	require.False(t, found, "nothing worked yet")

	endpoint := netip.MustParseAddrPort("162.159.192.7:2408")
	store := ep.scanStore()
	failover := &warpFailover{config: ep.options.WARPConfig, store: store, book: store.Book(edgescan.KindWARP), logger: hLogger(), probes: map[string]warpscan.Probe{}}
	failover.network = warpscan.NetworkInfo{Name: "wifi/IR"}
	failover.current = endpoint
	failover.noise = "sip"
	ep.rememberWay(failover)
	require.Contains(t, cache.saves, edgescan.SharedKey, "saved in the cache file")

	way, found := ep.lastWay(modeWireGuard)
	require.True(t, found)
	require.Equal(t, endpoint, way.Target.AddrPort)
	require.Equal(t, "sip", way.Method(wayNoise))
	_, found = ep.lastWay(modeAWG)
	require.False(t, found, "a way per tunnel")

	// the next start: a fresh failover, no network named yet
	next := &warpFailover{config: ep.options.WARPConfig, store: store, book: store.Book(edgescan.KindWARP), logger: hLogger(), probes: map[string]warpscan.Probe{}}
	var probed []netip.AddrPort
	next.probes["sip"] = func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		probed = append(probed, addrPort)
		return 20 * time.Millisecond, nil
	}
	rtt, answered := ep.tryLastWay(hTestContext(t), next, way)
	require.True(t, answered)
	require.Equal(t, 20*time.Millisecond, rtt)
	require.Equal(t, []netip.AddrPort{endpoint}, probed, "one handshake, with the way's endpoint")
	require.Equal(t, "sip", next.currentNoise(), "the inner endpoint starts with the way's noise")

	next.noise = ""
	attempts := 0
	next.probes["sip"] = func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		attempts++
		return 0, E.New("no answer")
	}
	_, answered = ep.tryLastWay(hTestContext(t), next, way)
	require.False(t, answered)
	require.Equal(t, edgescan.LastWayAttempts, attempts)
	require.Equal(t, "", next.currentNoise(), "a way that does not answer is not put in use")

	// a noise the scanner may no longer use is no way
	ep.options.Scanner.SearchNoise = false
	_, found = ep.lastWay(modeWireGuard)
	require.False(t, found)
	ep.options.Scanner.SearchNoise = true
	ep.options.Scanner.NoisePresets = []string{"dns-google"}
	_, found = ep.lastWay(modeWireGuard)
	require.False(t, found)
}

// Auto mode keeps the tunnel that connected and takes it at the next start without a race,
// unless it failed to connect, or the race was asked for.
func TestH_WARPLastTunnel(t *testing.T) {
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{}}
	ep := hNewWARP(t, service.ContextWith[adapter.CacheFile](hTestContext(t), cache), option.WARPEndpointOptions{
		Mode:    modeAuto,
		Scanner: &option.WARPScannerOptions{Enabled: true},
	})
	require.Empty(t, ep.lastTunnel())
	ep.rememberTunnel(modeAWG)
	require.Equal(t, modeAWG, ep.lastTunnel())

	ep.raceNext.Store(true)
	require.Empty(t, ep.lastTunnel(), "the last way did not answer: race")
	require.Equal(t, modeAWG, ep.lastTunnel(), "once")

	ep.failedModes.Store(modeAWG, struct{}{})
	require.Empty(t, ep.lastTunnel(), "it did not connect on this network")
	ep.clearFailedModes()
	require.Equal(t, modeAWG, ep.lastTunnel())
}
