package warpscan

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// The saved endpoints are probed before any random one, and only answering ones within max_rtt
// are returned, fastest first.
func TestH_ScanTriesSavedFirst(t *testing.T) {
	saved := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:2408"), netip.MustParseAddrPort("10.0.0.2:2408")}
	var access sync.Mutex
	var order []netip.AddrPort
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		access.Lock()
		order = append(order, addrPort)
		access.Unlock()
		switch addrPort {
		case saved[0]:
			return 30 * time.Millisecond, nil
		case saved[1]:
			return 10 * time.Millisecond, nil
		}
		return 0, errors.New("no answer")
	}
	options := &option.WARPScannerOptions{Concurrency: 1, Count: 20, CIDRs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("192.0.2.0/24")}, Ports: badoption.Listable[uint16]{1, 2}}
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), options, Defaults{}, saved, probe)
	require.NoError(t, err)
	require.Equal(t, saved, order[:2])
	require.Len(t, order, 20)
	require.Equal(t, []Result{{saved[1], 10 * time.Millisecond}, {saved[0], 30 * time.Millisecond}}, results)
	require.Equal(t, []netip.AddrPort{saved[1], saved[0]}, Kept(results))
}

// Slow endpoints are not accepted; a scan where nothing answers fails.
func TestH_ScanMaxRTTAndFailure(t *testing.T) {
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		return 2 * time.Second, nil
	}
	defaults := Defaults{CIDRs: WireGuardCIDRs, Ports: WireGuardPorts}
	_, err := Scan(context.Background(), log.NewNOPFactory().Logger(), &option.WARPScannerOptions{Count: 8}, defaults, nil, probe)
	require.ErrorContains(t, err, "no endpoint answered")
}

// A scan stops once enough endpoints answered.
func TestH_ScanStopsEarly(t *testing.T) {
	var access sync.Mutex
	probes := 0
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		access.Lock()
		probes++
		access.Unlock()
		return time.Millisecond, nil
	}
	defaults := Defaults{CIDRs: WireGuardCIDRs, Ports: WireGuardPorts}
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), &option.WARPScannerOptions{Count: 64, Concurrency: 1}, defaults, nil, probe)
	require.NoError(t, err)
	require.Len(t, results, enoughResults)
	require.Equal(t, enoughResults, probes)
}

// Random addresses stay inside their range.
func TestH_RandomAddress(t *testing.T) {
	for _, prefix := range []netip.Prefix{netip.MustParsePrefix("162.159.192.0/24"), netip.MustParsePrefix("2606:4700:103::/64"), netip.MustParsePrefix("10.1.2.3/32")} {
		for range 100 {
			require.True(t, prefix.Contains(randomAddress(prefix)), prefix)
		}
	}
}
