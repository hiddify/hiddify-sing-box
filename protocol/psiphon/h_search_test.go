package psiphon

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// As the first hop, an attempt ends with the search time; when it is up without a tunnel a deep
// search is offered, which has no time limit and runs the core in its aggressive mode.
func TestH_PsiphonSearch(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, option.PsiphonOutboundOptions{DataDirectory: t.TempDir()})
	require.NotNil(t, out.scanner, "the first hop scans")
	require.Equal(t, edgescan.PlatformDefault(16, 48), scannerDefaults.Concurrency)

	require.Equal(t, time.Minute, edgescan.DefaultSearchTimeout)
	start := time.Now().Add(-50 * time.Second)
	out.limitSearch(start)
	require.Equal(t, int(minAttempt/time.Second), *out.psiphon.config.EstablishTunnelTimeoutSeconds, "the attempt ends with the search")
	require.False(t, out.psiphon.config.AggressiveEstablishment)

	require.False(t, out.searchExhausted(time.Now()))
	require.False(t, adapter.DeepSearchAvailable(out))
	require.True(t, out.searchExhausted(time.Now().Add(-edgescan.DefaultSearchTimeout)))
	require.True(t, adapter.DeepSearchAvailable(out))

	require.NoError(t, out.StartDeepSearch())
	require.False(t, adapter.DeepSearchAvailable(out), "it runs")
	require.Len(t, out.reconnectCh, 1, "the deep search wakes the loop")
	<-out.reconnectCh
	out.searchWoken()
	require.True(t, out.scanner.status.IsDeep(), "woken by the deep search, which it runs")
	out.limitSearch(time.Now())
	require.Equal(t, int(deepAttempt/time.Second), *out.psiphon.config.EstablishTunnelTimeoutSeconds, "no limit, in attempts that each scan first")
	require.True(t, out.psiphon.config.AggressiveEstablishment)
	require.False(t, out.searchExhausted(time.Now().Add(-24*time.Hour)))

	out.searchFound()
	require.False(t, out.scanner.status.IsDeep())
	out.limitSearch(time.Now())
	require.InDelta(t, int(min(defaultEstablishTunnelTimeout, edgescan.DefaultSearchTimeout)/time.Second), *out.psiphon.config.EstablishTunnelTimeoutSeconds, 1, "a new search: an attempt is at most its time")
	require.NoError(t, out.Close())
}

// Behind another proxy there is no search: no time limit, no deep search.
func TestH_PsiphonSearchBehindDetour(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, option.PsiphonOutboundOptions{DataDirectory: t.TempDir(), UpstreamProxyURL: "socks5://127.0.0.1:1"})
	require.Nil(t, out.scanner)
	require.False(t, out.searchExhausted(time.Now().Add(-time.Hour)))
	require.Error(t, out.StartDeepSearch())
	require.NoError(t, out.Close())
}

// search_timeout is the one setting: a long one is a deep search from the start, with that limit;
// one below zero, a deep search without a limit.
func TestH_PsiphonDeepSearchOptions(t *testing.T) {
	t.Parallel()
	options := option.PsiphonOutboundOptions{DataDirectory: t.TempDir(), Scanner: &option.PsiphonScannerOptions{
		EdgeSearchOptions: option.EdgeSearchOptions{SearchTimeout: badoption.Duration(time.Hour)},
	}}
	out := newTestOutbound(t, options)
	out.limitSearch(time.Now())
	require.True(t, out.psiphon.config.AggressiveEstablishment, "a long search is a deep one")
	require.InDelta(t, 3600, *out.psiphon.config.EstablishTunnelTimeoutSeconds, 1)
	require.False(t, out.searchExhausted(time.Now().Add(-30*time.Minute)))
	require.True(t, out.searchExhausted(time.Now().Add(-time.Hour)))
	require.True(t, adapter.DeepSearchAvailable(out), "a deep search with a limit offers one without")
	require.NoError(t, out.StartDeepSearch())
	out.limitSearch(time.Now())
	require.InDelta(t, 3600, *out.psiphon.config.EstablishTunnelTimeoutSeconds, 1, "the asked deep search keeps the long limit")
	require.NoError(t, out.Close())

	options.DataDirectory = t.TempDir()
	options.Scanner.SearchTimeout = badoption.Duration(-1)
	out = newTestOutbound(t, options)
	out.limitSearch(time.Now())
	require.True(t, out.psiphon.config.AggressiveEstablishment)
	require.Equal(t, int(deepAttempt/time.Second), *out.psiphon.config.EstablishTunnelTimeoutSeconds, "no limit, in attempts that each scan first")
	require.False(t, out.searchExhausted(time.Now().Add(-24*time.Hour)))
	require.NoError(t, out.Close())
}

type hDirect struct {
	adapter.Outbound
	typ string
}

func (o hDirect) Type() string { return o.typ }

type hOutbounds struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m hOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

// A detour to a direct outbound makes Psiphon the first hop all the same: it scans, with every
// protocol; a detour to a proxy does not.
func TestH_PsiphonDirectDetour(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[adapter.OutboundManager](hTestContext(), hOutbounds{outbounds: map[string]adapter.Outbound{
		"direct": hDirect{typ: C.TypeDirect},
		"proxy":  hDirect{typ: C.TypeVLESS},
	}})
	create := func(detour string) *Outbound {
		options := option.PsiphonOutboundOptions{DataDirectory: t.TempDir()}
		options.Detour = detour
		out, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "psiphon-"+detour, options)
		require.NoError(t, err)
		return out.(*Outbound)
	}
	direct := create("direct")
	require.Nil(t, direct.scanner, "decided at the start, when every outbound exists")
	require.Equal(t, chainedProtocols, []string(direct.psiphon.config.LimitTunnelProtocols))
	require.True(t, scannerByDetour(direct.ctx, direct.options))
	require.NoError(t, direct.firstHopByDetour())
	require.NotNil(t, direct.scanner)
	require.Equal(t, firstHopProtocols, []string(direct.psiphon.config.LimitTunnelProtocols))
	require.False(t, direct.psiphon.config.DisableTactics)

	proxy := create("proxy")
	require.False(t, scannerByDetour(proxy.ctx, proxy.options))
}

// After a search gave up, Psiphon goes on trying with its backoff, the deep search still offered;
// another network takes the offer back, for a normal search there first; a deep search is only started once a search gave up, and once.
func TestH_PsiphonSearchKeepsTrying(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, option.PsiphonOutboundOptions{DataDirectory: t.TempDir()})
	require.NoError(t, out.StartDeepSearch())
	require.False(t, out.scanner.status.IsDeep(), "nothing gave up yet")
	require.True(t, out.searchExhausted(time.Now().Add(-edgescan.DefaultSearchTimeout)))
	require.NoError(t, out.StartDeepSearch())
	require.NoError(t, out.StartDeepSearch())
	require.True(t, out.scanner.status.IsDeep())
	require.Len(t, out.reconnectCh, 1, "one wake")
	out.searchFound()
	require.Empty(t, out.reconnectCh, "a wake asked for before the tunnel came up is done")

	require.True(t, out.searchExhausted(time.Now().Add(-edgescan.DefaultSearchTimeout)))
	out.InterfaceUpdated(out.ctx)
	require.Len(t, out.reconnectCh, 1, "another network wakes the loop")
	<-out.reconnectCh
	out.searchWoken()
	require.False(t, adapter.DeepSearchAvailable(out), "a normal search runs on the new network")
	require.NoError(t, out.Close())
}
