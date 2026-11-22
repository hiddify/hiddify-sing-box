package masque

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// The endpoint a tunnel connected to is kept per HTTP version, and the first scan of the next
// outbound takes it after one check, before it scans.
func TestH_MASQUELastWay(t *testing.T) {
	store := edgescan.OpenStore(nil, t.Name())
	var probed []netip.AddrPort
	answer := true
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		probed = append(probed, addrPort)
		if !answer {
			return 0, errors.New("no answer")
		}
		return 10 * time.Millisecond, nil
	}
	newScanner := func() *masqueScanner {
		return &masqueScanner{
			ctx: context.Background(), logger: log.NewNOPFactory().Logger(), store: store,
			book: store.Book(edgescan.KindWARPMASQUE), status: &warpscan.Status{},
			probes:    map[bool]warpscan.Probe{false: probe, true: probe},
			network:   warpscan.NetworkInfo{Name: "wifi/IR", IPv4: true},
			searching: map[bool]bool{}, found: map[bool]net.Addr{}, lastTried: map[bool]bool{},
		}
	}
	first := newScanner()
	require.Nil(t, first.tryLastWay(true, nil), "nothing connected yet")
	endpoint := netip.MustParseAddrPort("162.159.198.2:443")
	first.OnConnected(endpointAddr(endpoint, true), true, 50*time.Millisecond)

	next := newScanner()
	require.Nil(t, next.tryLastWay(false, nil), "a way per HTTP version")
	got := next.tryLastWay(true, nil)
	require.Equal(t, endpointAddr(endpoint, true).String(), got.String())
	require.Equal(t, []netip.AddrPort{endpoint}, probed)
	require.False(t, next.status.IsScanning())
	require.Nil(t, next.tryLastWay(true, nil), "once per outbound")

	answer = false
	require.Nil(t, newScanner().tryLastWay(true, nil), "a way that does not answer: the scan")
}
