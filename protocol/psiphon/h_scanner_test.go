package psiphon

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The scanner runs when Psiphon is the first hop, not behind another proxy, unless asked.
func TestH_PsiphonScannerEnabled(t *testing.T) {
	t.Parallel()
	on, off := true, false
	require.True(t, scannerEnabled(option.PsiphonOutboundOptions{}))
	behind := option.PsiphonOutboundOptions{}
	behind.Detour = "select"
	require.False(t, scannerEnabled(behind), "extra security: the main proxy already gets out")
	require.False(t, scannerEnabled(option.PsiphonOutboundOptions{UpstreamProxyURL: "socks5://127.0.0.1:1"}))
	behind.Scanner = &option.PsiphonScannerOptions{Enabled: &on}
	require.True(t, scannerEnabled(behind))
	require.False(t, scannerEnabled(option.PsiphonOutboundOptions{Scanner: &option.PsiphonScannerOptions{Enabled: &off}}))
}

// As the first hop the core tries every protocol but in-proxy, with its CDN fronting scan;
// behind a proxy, the TCP ones without tactics. The names are the core's, so its config commits.
func TestH_PsiphonTunnelProtocols(t *testing.T) {
	t.Parallel()
	for _, name := range append(append([]string{}, firstHopProtocols...), chainedProtocols...) {
		require.True(t, protocol.TunnelProtocolIsCompatibleWithInproxy(name) || !protocol.TunnelProtocolUsesInproxy(name), name)
		require.Contains(t, protocol.SupportedTunnelProtocols, name)
	}
	first, err := buildConfig(option.PsiphonOutboundOptions{DataDirectory: t.TempDir()}, time.Minute, "first")
	require.NoError(t, err)
	require.Equal(t, firstHopProtocols, []string(first.LimitTunnelProtocols))
	require.True(t, first.FrontedMeekCDNScanUseBuiltInSpec)
	require.False(t, first.DisableTactics)
	require.Zero(t, *first.InproxyTunnelProtocolSelectionProbability)
	require.Equal(t, defaultClientPlatform, first.ClientPlatform)
	require.NoError(t, os.MkdirAll(first.DataRootDirectory, 0o755))
	require.NoError(t, first.Commit(false))

	behind := option.PsiphonOutboundOptions{DataDirectory: t.TempDir()}
	behind.Detour = "select"
	chained, err := buildConfig(behind, time.Minute, "chained")
	require.NoError(t, err)
	require.Equal(t, chainedProtocols, []string(chained.LimitTunnelProtocols))
	require.False(t, chained.FrontedMeekCDNScanUseBuiltInSpec)
	require.True(t, chained.DisableTactics)
	require.NoError(t, os.MkdirAll(chained.DataRootDirectory, 0o755))
	require.NoError(t, chained.Commit(false))
}

// Every built-in edge is an IPv4 range, and every set has server names.
func TestH_PsiphonCDNEdgeSets(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, cdnEdgeSets)
	for _, set := range cdnEdgeSets {
		require.NotEmpty(t, set.serverNames, set.name)
		for _, cidr := range set.cidrs {
			prefix, err := netip.ParsePrefix(cidr)
			require.NoError(t, err, set.name)
			require.True(t, prefix.Addr().Is4(), cidr)
		}
	}
	s := &edgeScanner{options: option.PsiphonScannerOptions{Sets: []string{"built-in-fastly", "cloudflare"}}}
	sets := s.sets()
	require.Len(t, sets, 2)
	require.Equal(t, "fastly", sets[0].Name)
	require.Equal(t, "", sets[0].ServerNames[0], "each edge is also tried without a server name")
}

// The edge the core connected over is read from its notice and gains a point.
func TestH_PsiphonFrontingFoundNotice(t *testing.T) {
	t.Parallel()
	target, ok := parseFrontingFound(NoticeEvent{Type: "Info", Data: map[string]interface{}{"message": `cdn fronting scan found (ip: 23\.12\.147\.13, sni: a.akamaihd.net)`}})
	require.True(t, ok)
	require.Equal(t, edgescan.Target{AddrPort: netip.MustParseAddrPort("23.12.147.13:443"), ServerName: "a.akamaihd.net"}, target)
	target, ok = parseFrontingFound(NoticeEvent{Type: "Info", Data: map[string]interface{}{"message": `cdn fronting scan found (ip: 23\.12\.147\.13, sni: none)`}})
	require.True(t, ok)
	require.Empty(t, target.ServerName)
	_, ok = parseFrontingFound(NoticeEvent{Type: "Info", Data: map[string]interface{}{"message": "cdn fronting scan progress (attempts: 50, working: 0)"}})
	require.False(t, ok)

	s := &edgeScanner{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), store: edgescan.OpenStore(nil, t.Name()), book: edgescan.NewBook(), network: edgescan.NetworkInfo{Name: "home"}}
	s.onNotice(NoticeEvent{Type: "Info", Data: map[string]interface{}{"message": `cdn fronting scan found (ip: 23\.12\.147\.13, sni: a.akamaihd.net)`}})
	preferred, _ := s.book.CandidateTargets("home")
	require.Equal(t, []edgescan.Target{{AddrPort: netip.MustParseAddrPort("23.12.147.13:443"), ServerName: "a.akamaihd.net"}}, preferred)
}

// The core gets one override per CDN and server name, matched to the server entries that front
// through that CDN, by their fronting domains or addresses.
func TestH_PsiphonFrontingOverrides(t *testing.T) {
	t.Parallel()
	result := func(address, name string) edgescan.Result {
		return edgescan.Result{Target: edgescan.Target{AddrPort: netip.MustParseAddrPort(address), ServerName: name}}
	}
	overrides := frontingOverrides([]edgescan.Result{
		result("151.101.128.223:443", ""),             // fastly, from the curated set too
		result("199.232.19.60:443", ""),               // fastly
		result("142.251.150.6:443", "www.google.com"), // google
		result("192.0.2.1:443", ""),                   // no CDN
		result("199.232.19.61:443", ""),               // a third fastly edge: over the limit
	}, 2, edgeSet)
	require.Len(t, overrides, 2)
	fastly, google := overrides[0], overrides[1]
	require.Equal(t, []string{"151.101.128.223", "199.232.19.60"}, fastly.DialAddresses)
	require.True(t, fastly.DisableSNI)
	require.Equal(t, "www.google.com", google.SNIServerName)
	require.Empty(t, google.VerifyServerNames, "an edge may answer with its own certificate")
	require.NoError(t, overrides.Validate(nil))

	match := func(override *parameters.FrontedMeekDialOverride, address string) bool {
		return regexp.MustCompile(override.MatchDialAddressRegexes[0]).MatchString(address)
	}
	require.True(t, match(fastly, "m.sni.global.fastly.net"))
	require.True(t, match(fastly, "151.101.1.57"))
	require.False(t, match(fastly, "104.18.167.46"), "a Cloudflare server entry")
	require.False(t, match(fastly, "151.10.1.1"))
	require.True(t, match(google, "142.251.151.1"))
}

// The range regex matches the addresses of its prefixes only.
func TestH_PsiphonRangeRegex(t *testing.T) {
	t.Parallel()
	regex := regexp.MustCompile(rangeRegex([]string{"104.16.0.0/13", "151.101.0.0/16", "23.12.147.13/32", "103.245.222.0/23"}))
	for address, want := range map[string]bool{
		"104.16.0.1":    true,
		"104.23.255.1":  true,
		"104.24.0.1":    false,
		"151.101.9.9":   true,
		"23.12.147.13":  true,
		"23.12.147.130": false,
		"103.245.223.1": true,
		"103.245.224.1": false,
	} {
		require.Equal(t, want, regex.MatchString(address), address)
	}
}

// The scanner keeps the edges and server names whose handshake completes, whatever the
// certificate; a name the network filters (the handshake fails) is left out.
func TestH_PsiphonScannerProbe(t *testing.T) {
	t.Parallel()
	server := httptest.NewUnstartedServer(nil)
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == "blocked.invalid" {
			return nil, errors.New("filtered")
		}
		return nil, nil
	}}
	server.StartTLS()
	defer server.Close()
	addrPort := netip.MustParseAddrPort(server.Listener.Addr().String())
	s := &edgeScanner{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		dialer: N.SystemDialer,
		store:  edgescan.OpenStore(nil, t.Name()),
		book:   edgescan.NewBook(),
		port:   addrPort.Port(),
		options: option.PsiphonScannerOptions{
			CIDRs:       badoption.Listable[netip.Prefix]{netip.PrefixFrom(addrPort.Addr(), 32)},
			ServerNames: []string{"example.com", "blocked.invalid"},
		},
	}
	target := func(name string) edgescan.Target { return edgescan.Target{AddrPort: addrPort, ServerName: name} }
	_, err := s.probe(context.Background(), target("example.com"))
	require.NoError(t, err)
	_, err = s.probe(context.Background(), target("blocked.invalid"))
	require.Error(t, err)
	_, err = s.probe(context.Background(), target(""))
	require.NoError(t, err)

	_, results, err := s.Scan()
	require.NoError(t, err)
	var answered []string
	for _, result := range results {
		answered = append(answered, result.ServerName)
	}
	require.ElementsMatch(t, []string{"", "example.com"}, answered)
	_, err = s.probe(context.Background(), target("other.example"))
	require.NoError(t, err, "a name the edge has no certificate for still fronts")
}

// Against the real CDN edges: the scanner finds some that answer. HIDDIFY_PSIPHON_E2E=1.
func TestH_PsiphonScannerLive(t *testing.T) {
	if os.Getenv("HIDDIFY_PSIPHON_E2E") == "" {
		t.Skip("set HIDDIFY_PSIPHON_E2E=1")
	}
	s := newEdgeScanner(context.Background(), log.NewNOPFactory().Logger(), N.SystemDialer, nil, "live", "")
	s.resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	}
	network, results, err := s.Scan()
	require.NoError(t, err)
	t.Log("network ", network.Name)
	for _, result := range results {
		t.Log(result.Target, " ", result.RTT)
	}
	overrides := frontingOverrides(results, defaultScannerCandidates, s.setOf)
	require.NotEmpty(t, overrides)
	for _, override := range overrides {
		t.Log(override.OverrideID, override.DialAddresses, override.SNIServerName)
	}
}

// The names of each set resolve to its seeds, the sets taking turns; names that are not real and
// addresses that are not public are left out, and a seed counts for the set it came from.
func TestH_PsiphonSeeds(t *testing.T) {
	t.Parallel()
	answers := map[string][]netip.Addr{
		"a.example": {netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")},
		"b.example": {netip.MustParseAddr("10.10.34.35")}, // poisoned
		"c.example": {netip.MustParseAddr("198.51.100.20")},
	}
	s := &edgeScanner{ctx: context.Background(), port: 443, resolve: func(ctx context.Context, name string) ([]netip.Addr, error) {
		require.NotEqual(t, "x.redirect", name)
		return answers[name], nil
	}}
	seeds, setOf := s.seeds([]edgescan.Set{
		{Name: "one", ServerNames: []string{"", "a.example", "b.example", "x.redirect"}},
		{Name: "two", ServerNames: []string{"", "c.example"}},
	})
	require.Equal(t, []edgescan.Target{
		{AddrPort: netip.MustParseAddrPort("192.0.2.10:443"), ServerName: "a.example"},
		{AddrPort: netip.MustParseAddrPort("198.51.100.20:443"), ServerName: "c.example"},
	}, seeds)
	require.Equal(t, "two", setOf[netip.MustParseAddr("198.51.100.20")])
}
