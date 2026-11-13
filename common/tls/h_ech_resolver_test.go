package tls

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type hECHTestConfig struct {
	ECHCapableConfig
	echConfigList []byte
}

func (c *hECHTestConfig) ServerName() string           { return "example.org" }
func (c *hECHTestConfig) ECHConfigList() []byte        { return c.echConfigList }
func (c *hECHTestConfig) SetECHConfigList(list []byte) { c.echConfigList = list }
func (c *hECHTestConfig) Clone() Config                { return &hECHTestConfig{echConfigList: c.echConfigList} }

// hECHTestRouter answers HTTPS queries with an ECH config and the TTL a DNS rule may rewrite it to.
type hECHTestRouter struct {
	adapter.DNSRouter
	ttl     uint32
	queries int
	name    string
	options adapter.DNSQueryOptions
}

func (r *hECHTestRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	r.queries++
	r.name = message.Question[0].Name
	r.options = options
	record := &mDNS.HTTPS{SVCB: mDNS.SVCB{
		Hdr:   mDNS.RR_Header{Name: r.name, Rrtype: mDNS.TypeHTTPS, Class: mDNS.ClassINET, Ttl: r.ttl},
		Value: []mDNS.SVCBKeyValue{&mDNS.SVCBECHConfig{ECH: []byte("ech-config-list")}},
	}}
	return &mDNS.Msg{MsgHdr: mDNS.MsgHdr{Response: true, Rcode: mDNS.RcodeSuccess}, Answer: []mDNS.RR{record}}, nil
}

func hECHTestClient(t *testing.T, ttl uint32) (*hECHTestRouter, *ECHClientConfig) {
	t.Helper()
	router := &hECHTestRouter{ttl: ttl}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), router)
	config, err := parseECHClientConfig(ctx, &hECHTestConfig{}, option.OutboundTLSOptions{
		ECH: &option.OutboundECHOptions{Enabled: true, QueryServerName: "cloudflare-ech.com"},
	})
	require.NoError(t, err)
	client := config.(*ECHClientConfig)
	require.NoError(t, client.FetchConfig(context.Background()))
	require.Equal(t, "cloudflare-ech.com.", router.name)
	require.Equal(t, "ech-config-list", string(client.ECHConfigList()))
	return router, client
}

// The ECH config is fetched through the DNS resolvers by the rules (no transport is forced), and
// never from the DNS cache, whose TTLs a config may stretch to a day (hiddify-app#2539).
func TestH_ECHFetchSkipsDNSCache(t *testing.T) {
	router, _ := hECHTestClient(t, 300)
	require.Nil(t, router.options.Transport)
	require.True(t, router.options.DisableCache)
}

// A fetched ECH config is kept for the record's TTL, at most 10 minutes, then fetched again.
func TestH_ECHConfigKeptAtMostTenMinutes(t *testing.T) {
	for _, test := range []struct {
		ttl  uint32
		kept time.Duration
	}{
		{ttl: 86400, kept: 10 * time.Minute},
		{ttl: 601, kept: 10 * time.Minute},
		{ttl: 300, kept: 5 * time.Minute},
	} {
		router, client := hECHTestClient(t, test.ttl)
		require.Equal(t, test.kept, client.lastTTL, test.ttl)

		require.NoError(t, client.FetchConfig(context.Background()))
		require.Equal(t, 1, router.queries, "a fresh config is not fetched again")

		client.lastUpdate = time.Now().Add(-test.kept - time.Second)
		require.NoError(t, client.FetchConfig(context.Background()))
		require.Equal(t, 2, router.queries, "an expired config is fetched again")
	}
}

// A clone keeps the fetched config until it expires, instead of a DNS query per connection.
func TestH_ECHCloneKeepsConfig(t *testing.T) {
	router, client := hECHTestClient(t, 86400)
	clone := client.Clone().(*ECHClientConfig)
	require.NoError(t, clone.FetchConfig(context.Background()))
	require.Equal(t, 1, router.queries)
	require.Equal(t, 10*time.Minute, clone.lastTTL)
}
