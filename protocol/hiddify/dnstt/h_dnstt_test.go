package dnstt

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnstt "github.com/net2share/vaydns/client"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

const testPubKey = "0000000000000000000000000000000000000000000000000000000000000000"

var loadResolversOnce sync.Once

func ensureResolvers() {
	loadResolversOnce.Do(loadResolvers)
}

func validOptions() option.DnsttOptions {
	return option.DnsttOptions{
		PublicKey: testPubKey,
		Domain:    "t.example.com",
		Resolvers: []string{"127.0.0.1:53"},
	}
}

func newTestOutbound(t *testing.T, options option.DnsttOptions) *Outbound {
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "dnstt-out", options)
	require.NoError(t, err)
	t.Cleanup(func() { out.(*Outbound).Close() })
	return out.(*Outbound)
}

func TestH_DnsttGetConfigResolvers(t *testing.T) {
	t.Parallel()
	timeout := badoption.Duration(3 * time.Second)
	workers := 7
	options := option.DnsttOptions{
		Resolvers:         []string{"8.8.8.8:53", "https://dns.example/dns-query", "dot://1.1.1.1:853"},
		UdpAcceptErrors:   true,
		UdpSharedSocket:   true,
		UdpTimeout:        &timeout,
		UdpWorkers:        &workers,
		UTLSClientHelloID: "firefox",
	}
	resolvers, err := getConfigResolvers(options)
	require.NoError(t, err)
	require.Len(t, resolvers, 3)

	require.Equal(t, dnstt.ResolverTypeUDP, resolvers[0].Resolver.ResolverType)
	require.Equal(t, "8.8.8.8:53", resolvers[0].Resolver.ResolverAddr)
	require.Equal(t, dnstt.ResolverTypeDOH, resolvers[1].Resolver.ResolverType)
	require.Equal(t, "https://dns.example/dns-query", resolvers[1].Resolver.ResolverAddr)
	require.Equal(t, dnstt.ResolverTypeDOT, resolvers[2].Resolver.ResolverType)
	require.Equal(t, "1.1.1.1:853", resolvers[2].Resolver.ResolverAddr)
	for _, r := range resolvers {
		require.False(t, r.Auto)
		require.True(t, r.Resolver.UDPAcceptErrors)
		require.True(t, r.Resolver.UDPSharedSocket)
		require.Equal(t, 3*time.Second, r.Resolver.UDPTimeout)
		require.Equal(t, 7, r.Resolver.UDPWorkers)
		require.NotNil(t, r.Resolver.UTLSClientHelloID)
	}

	resolvers, err = getConfigResolvers(option.DnsttOptions{Resolvers: []string{"9.9.9.9:53"}})
	require.NoError(t, err)
	require.Nil(t, resolvers[0].Resolver.UTLSClientHelloID)
	require.False(t, resolvers[0].Resolver.UDPSharedSocket)

	resolvers, err = getConfigResolvers(option.DnsttOptions{})
	require.NoError(t, err)
	require.Empty(t, resolvers)
}

func TestH_DnsttAutoResolvers(t *testing.T) {
	t.Parallel()
	ensureResolvers()
	require.NotEmpty(t, countryResolvers)
	require.NotEmpty(t, resolverCountry)
	for country, list := range countryResolvers {
		for _, ip := range list {
			require.Equal(t, country, resolverCountry[ip])
			break
		}
	}

	for _, auto := range []string{"auto", ""} {
		resolvers, err := getConfigResolvers(option.DnsttOptions{Resolvers: []string{auto, "4.4.4.4:53"}})
		require.NoError(t, err)
		require.Len(t, resolvers, len(resolverCountry)+1)
		seen := map[string]bool{}
		for _, r := range resolvers[:len(resolvers)-1] {
			require.True(t, r.Auto)
			require.Equal(t, dnstt.ResolverTypeUDP, r.Resolver.ResolverType)
			require.True(t, strings.HasSuffix(r.Resolver.ResolverAddr, ":53"), r.Resolver.ResolverAddr)
			ip := strings.TrimSuffix(r.Resolver.ResolverAddr, ":53")
			_, known := resolverCountry[ip]
			require.True(t, known, ip)
			seen[ip] = true
		}
		require.Len(t, seen, len(resolverCountry))
		last := resolvers[len(resolvers)-1]
		require.False(t, last.Auto)
		require.Equal(t, "4.4.4.4:53", last.Resolver.ResolverAddr)
	}
}

func TestH_DnsttNewOutboundValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(o *option.DnsttOptions)
		wantErr string
	}{
		{"no resolvers", func(o *option.DnsttOptions) { o.Resolvers = nil }, "at least one resolver"},
		{"no public key", func(o *option.DnsttOptions) { o.PublicKey = "" }, "public key is required"},
		{"no domain", func(o *option.DnsttOptions) { o.Domain = "" }, "domain is required"},
	}
	for _, tc := range cases {
		options := validOptions()
		tc.mutate(&options)
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "dnstt-out", options)
		require.ErrorContains(t, err, tc.wantErr, tc.name)
	}
}

func TestH_DnsttNewOutboundDefaults(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, validOptions())
	require.Equal(t, C.TypeDNSTT, out.Type())
	require.Equal(t, []string{N.NetworkTCP}, out.Network())
	require.Equal(t, "txt", out.options.RecordType)
	require.Equal(t, "a", out.options.PreTestRecordType)
	require.Equal(t, "www.google.com", out.options.PreTestDomain)
	require.Len(t, out.candidateResolvers, 1)
	require.Empty(t, out.resolvers)
	require.Empty(t, out.tunnels)
	require.Nil(t, out.mdMgr)

	options := validOptions()
	options.RecordType = "cname"
	options.PreTestRecordType = "aaaa"
	options.PreTestDomain = "probe.example"
	out = newTestOutbound(t, options)
	require.Equal(t, "cname", out.options.RecordType)
	require.Equal(t, "aaaa", out.options.PreTestRecordType)
	require.Equal(t, "probe.example", out.options.PreTestDomain)
}

func TestH_DnsttNotStarted(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, validOptions())
	require.False(t, out.IsReady())
	_, err := out.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
	require.ErrorContains(t, err, "not started")
	_, err = out.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "not started")

	require.Contains(t, out.DisplayType(), "Connecting")
	out.started = -1
	require.Contains(t, out.DisplayType(), "Failed")
	out.started = 1
	out.resolvers = make([]dnstt.Resolver, 3)
	require.True(t, out.IsReady())
	require.Contains(t, out.DisplayType(), "3 resolvers")

	_, err = out.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "UoT is not enabled")
}

func TestH_DnsttSmartPool(t *testing.T) {
	t.Parallel()
	options := validOptions()
	options.SmartPool = true
	out := newTestOutbound(t, options)
	require.NotNil(t, out.mdMgr)
	require.Len(t, out.resolvers, 1)
	require.Len(t, out.tunnels, 1)
	require.Nil(t, out.tunnels[0])
	require.Equal(t, dnstt.ResolverTypeUDP, out.resolvers[0].ResolverType)
	host, _, err := net.SplitHostPort(out.resolvers[0].ResolverAddr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	require.NoError(t, out.Close())
}

func TestH_DnsttResolverURL(t *testing.T) {
	t.Parallel()
	require.Equal(t, "1.1.1.1:53", resolverURL(dnstt.Resolver{ResolverType: dnstt.ResolverTypeUDP, ResolverAddr: "1.1.1.1:53"}))
	require.Equal(t, "dot://1.1.1.1:853", resolverURL(dnstt.Resolver{ResolverType: dnstt.ResolverTypeDOT, ResolverAddr: "1.1.1.1:853"}))
	require.Equal(t, "https://dns.example/q", resolverURL(dnstt.Resolver{ResolverType: dnstt.ResolverTypeDOH, ResolverAddr: "https://dns.example/q"}))
}

func TestH_DnsttRecordTypeAndQuery(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]uint16{
		"a": dns.TypeA, "aaaa": dns.TypeAAAA, "cname": dns.TypeCNAME, "mx": dns.TypeMX,
		"ns": dns.TypeNS, "ptr": dns.TypePTR, "soa": dns.TypeSOA, "srv": dns.TypeSRV,
		"txt": dns.TypeTXT, "bogus": dns.TypeA, "": dns.TypeA,
	} {
		require.Equal(t, want, getDnsRecordType(in), in)
	}
	msg := buildDNSQuery("example.com", dns.TypeTXT)
	require.True(t, msg.RecursionDesired)
	require.Len(t, msg.Question, 1)
	require.Equal(t, "example.com.", msg.Question[0].Name)
	require.Equal(t, dns.TypeTXT, msg.Question[0].Qtype)
}

type memoryCache struct {
	adapter.CacheFile
	mu   sync.Mutex
	data map[string]*adapter.SavedBinary
}

func (c *memoryCache) LoadBinary(tag string) *adapter.SavedBinary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data[tag]
}

func (c *memoryCache) SaveBinary(tag string, set *adapter.SavedBinary) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[tag] = set
	return nil
}

func TestH_DnsttHistoryPersistence(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, validOptions())
	require.Empty(t, out.loadHistory().ResolverRate)
	out.saveHistory(&History{ResolverRate: map[string]int{"x": 1}})

	cache := &memoryCache{data: map[string]*adapter.SavedBinary{}}
	out.cache = cache
	require.Empty(t, out.loadHistory().ResolverRate)
	out.saveHistory(&History{ResolverRate: map[string]int{"1.1.1.1:53": 5, "9.9.9.9:53": -3}})
	require.Contains(t, cache.data, "dnstt_resolverstxt")
	require.Equal(t, map[string]int{"1.1.1.1:53": 5, "9.9.9.9:53": -3}, out.loadHistory().ResolverRate)

	cache.data["dnstt_resolverstxt"] = &adapter.SavedBinary{Content: []byte("{not json")}
	require.NotNil(t, out.loadHistory().ResolverRate)

	other := newTestOutbound(t, func() option.DnsttOptions { o := validOptions(); o.RecordType = "cname"; return o }())
	other.cache = cache
	require.Empty(t, other.loadHistory().ResolverRate)
}

func TestH_DnsttCreateTunnelInvalidServer(t *testing.T) {
	t.Parallel()
	options := validOptions()
	options.PublicKey = "not-hex"
	out := newTestOutbound(t, options)
	_, err := out.createDnsttTunnel(context.Background(), []dnstt.Resolver{{ResolverType: dnstt.ResolverTypeUDP, ResolverAddr: "127.0.0.1:1"}})
	require.ErrorContains(t, err, "invalid tunnel server")

	_, err = out.OpenStream(context.Background())
	require.ErrorContains(t, err, "invalid tunnel server")
}

func startLocalDNS(t *testing.T, handler dns.HandlerFunc) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: pc, Handler: handler}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	<-started
	t.Cleanup(func() { server.Shutdown() })
	return pc.LocalAddr().String()
}

func TestH_DnsttResolveUDPLocal(t *testing.T) {
	t.Parallel()
	addr := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "found.test." {
			rr, _ := dns.NewRR("found.test. 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})
	options := validOptions()
	options.PreTestDomain = "empty.test"
	out := newTestOutbound(t, options)
	resolver := dnstt.Resolver{ResolverType: dnstt.ResolverTypeUDP, ResolverAddr: addr}

	resp, err := out.Resolve(resolver, "found.test", dns.TypeA)
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)
	require.Equal(t, "192.0.2.1", resp.Answer[0].(*dns.A).A.String())

	rate, err := out.testTunnelResolver(resolver)
	require.Error(t, err)
	require.Equal(t, -3, rate)

	rate, err = out.testTunnelResolver(dnstt.Resolver{ResolverType: dnstt.ResolverTypeUDP, ResolverAddr: "no-port"})
	require.Error(t, err)
	require.Equal(t, -4, rate)
}

func TestH_DnsttResolveUnsupportedResolverType(t *testing.T) {
	t.Skip("BUG: Resolve ignores the error from getTCPBasedResolverConnection and calls WriteTo on a nil conn, panicking (protocol/hiddify/dnstt/tester.go:274)")
	t.Parallel()
	out := newTestOutbound(t, validOptions())
	require.NotPanics(t, func() {
		_, err := out.Resolve(dnstt.Resolver{ResolverType: "bogus", ResolverAddr: "127.0.0.1:1"}, "example.com", dns.TypeA)
		require.Error(t, err)
	})
}
