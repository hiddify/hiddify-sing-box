package warp

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// A restart clears the endpoint's failover while a scan of the old start still runs (a network
// change starts one in the background). The scan read the field again to save its scores and
// crashed the packet tunnel with a nil pointer; it keeps using the failover it started with.
func TestH_WARPScanSurvivesARestart(t *testing.T) {
	ep := hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{
		WARPConfig: hWARPConfig(t, hWARPConfigJSON),
		Scanner:    &option.WARPScannerOptions{Enabled: true, Count: 2, Timeout: badoption.Duration(time.Second)},
	})
	var cleared atomic.Bool
	answers := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		if cleared.CompareAndSwap(false, true) { // what restart does, while the scan probes
			ep.mtx.Lock()
			ep.failover = nil
			ep.mtx.Unlock()
		}
		return time.Millisecond, nil
	}
	failover := &warpFailover{
		config:  ep.options.WARPConfig,
		book:    warpscan.NewBook(),
		logger:  hLogger(),
		probes:  map[string]warpscan.Probe{"": answers},
		network: warpscan.NetworkInfo{Name: "wifi/IR", IPv4: true},
	}
	ep.failover = failover

	results, err := ep.scan(nil)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	require.True(t, cleared.Load(), "the failover was cleared during the scan")
}
