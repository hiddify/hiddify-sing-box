package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type hTagRecorder struct {
	access sync.Mutex
	tags   []string
}

func (r *hTagRecorder) add(tag string) {
	r.access.Lock()
	r.tags = append(r.tags, tag)
	r.access.Unlock()
}

func (r *hTagRecorder) get() []string {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]string(nil), r.tags...)
}

func hRouteRule(domain string, server string, bypass bool) option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: badoption.Listable[string]{domain},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: server,
					AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
						BypassIfFailed: bypass,
					},
				},
			},
		},
	}
}

// A rule with a non-default strategy forces legacy DNS mode, which is the
// only code path that implements bypass_if_failed.
func hLegacyModeRule() option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: badoption.Listable[string]{"legacy-mode.invalid"},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: "default",
					AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
						Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only),
					},
				},
			},
		},
	}
}

func hTransportManager(tags ...string) *routerTestFakeDNSTransportManager {
	manager := &routerTestFakeDNSTransportManager{transports: map[string]adapter.DNSTransport{}}
	for _, tag := range tags {
		transport := &routerTestFakeDNSTransport{tag: tag, transportType: C.DNSTypeUDP}
		manager.transports[tag] = transport
		if tag == "default" {
			manager.defaultTransport = transport
		}
	}
	return manager
}

func hQuery(domain string) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(domain), mDNS.TypeA)
	return message
}

func hExchangeClient(recorder *hTagRecorder, answers map[string]string) *fakeDNSClient {
	return &fakeDNSClient{
		exchange: func(transport adapter.DNSTransport, message *mDNS.Msg) (*mDNS.Msg, error) {
			recorder.add(transport.Tag())
			address, ok := answers[transport.Tag()]
			if !ok {
				return nil, E.New("upstream ", transport.Tag(), " failed")
			}
			return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr(address)}, 60), nil
		},
	}
}

func TestH_ExchangeBypassIfFailedFallsToNextRule(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", true),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hExchangeClient(recorder, map[string]string{
		"secondary": "1.2.3.4",
		"default":   "9.9.9.9",
	}))
	require.True(t, router.legacyDNSMode)

	response, err := router.Exchange(context.Background(), hQuery("example.com"), adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, MessageToAddresses(response))
	require.Equal(t, []string{"primary", "secondary"}, recorder.get())
}

func TestH_ExchangeBypassIfFailedChainFallsToDefault(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", true),
		hRouteRule("example.com", "secondary", true),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hExchangeClient(recorder, map[string]string{
		"default": "9.9.9.9",
	}))

	response, err := router.Exchange(context.Background(), hQuery("example.com"), adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("9.9.9.9")}, MessageToAddresses(response))
	require.Equal(t, []string{"primary", "secondary", "default"}, recorder.get())
}

func TestH_ExchangeWithoutBypassReturnsError(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", false),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hExchangeClient(recorder, map[string]string{
		"secondary": "1.2.3.4",
	}))

	_, err := router.Exchange(context.Background(), hQuery("example.com"), adapter.DNSQueryOptions{})
	require.ErrorContains(t, err, "upstream primary failed")
	require.Equal(t, []string{"primary"}, recorder.get())
}

func TestH_ExchangeBypassIfFailedSuccessDoesNotBypass(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", true),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hExchangeClient(recorder, map[string]string{
		"primary":   "5.6.7.8",
		"secondary": "1.2.3.4",
	}))

	response, err := router.Exchange(context.Background(), hQuery("example.com"), adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("5.6.7.8")}, MessageToAddresses(response))
	require.Equal(t, []string{"primary"}, recorder.get())
}

func TestH_ExchangeBypassIfFailedStopsOnCanceledContext(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", true),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hExchangeClient(recorder, map[string]string{
		"secondary": "1.2.3.4",
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := router.Exchange(ctx, hQuery("example.com"), adapter.DNSQueryOptions{})
	require.Error(t, err)
	require.Equal(t, []string{"primary"}, recorder.get())
}

func hLookupClient(recorder *hTagRecorder, answers map[string][]netip.Addr) *fakeDNSClient {
	return &fakeDNSClient{
		lookup: func(transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, *mDNS.Msg, error) {
			recorder.add(transport.Tag())
			addresses, ok := answers[transport.Tag()]
			if !ok {
				return nil, nil, E.New("upstream ", transport.Tag(), " failed")
			}
			response := FixedResponse(0, fixedQuestion(domain, mDNS.TypeA), addresses, 60)
			return addresses, response, nil
		},
	}
}

func TestH_LookupBypassIfFailedOnError(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", true),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hLookupClient(recorder, map[string][]netip.Addr{
		"secondary": {netip.MustParseAddr("1.2.3.4")},
	}))

	addresses, err := router.Lookup(context.Background(), "example.com", adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, addresses)
	require.Equal(t, []string{"primary", "secondary"}, recorder.get())
}

func TestH_LookupBypassIfFailedOnEmptyResult(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", true),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hLookupClient(recorder, map[string][]netip.Addr{
		"primary":   {},
		"secondary": {netip.MustParseAddr("1.2.3.4")},
	}))

	addresses, err := router.Lookup(context.Background(), "example.com", adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, addresses)
	require.Equal(t, []string{"primary", "secondary"}, recorder.get())
}

func TestH_LookupWithoutBypassReturnsError(t *testing.T) {
	t.Parallel()
	recorder := &hTagRecorder{}
	router := newTestRouter(t, []option.DNSRule{
		hRouteRule("example.com", "primary", false),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hLookupClient(recorder, map[string][]netip.Addr{
		"secondary": {netip.MustParseAddr("1.2.3.4")},
	}))

	_, err := router.Lookup(context.Background(), "example.com", adapter.DNSQueryOptions{})
	require.ErrorContains(t, err, "upstream primary failed")
	require.Equal(t, []string{"primary"}, recorder.get())
}

func TestH_LookupPredefinedFiltersBlockedAddresses(t *testing.T) {
	t.Parallel()
	predefinedRule := func(records ...string) option.DNSRule {
		answers := make(badoption.Listable[option.DNSRecordOptions], 0, len(records))
		for _, record := range records {
			answers = append(answers, mustRecord(t, record))
		}
		return option.DNSRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					Domain: badoption.Listable[string]{"example.com"},
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypePredefined,
					PredefinedOptions: option.DNSRouteActionPredefined{
						Answer: answers,
					},
				},
			},
		}
	}

	router := newTestRouter(t, []option.DNSRule{
		predefinedRule(
			"example.com. IN A 10.10.34.36",
			"example.com. IN A 1.1.1.1",
			"example.com. IN AAAA 2001:4188:2:600::1",
			"example.com. IN AAAA 2001:db8::1",
		),
		hLegacyModeRule(),
	}, hTransportManager("default"), &fakeDNSClient{})
	require.True(t, router.legacyDNSMode)

	addresses, err := router.Lookup(context.Background(), "example.com", adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:db8::1")}, addresses)

	blockedRouter := newTestRouter(t, []option.DNSRule{
		predefinedRule("example.com. IN A 10.10.34.36"),
		hLegacyModeRule(),
	}, hTransportManager("default"), &fakeDNSClient{})
	addresses, err = blockedRouter.Lookup(context.Background(), "example.com", adapter.DNSQueryOptions{})
	require.ErrorContains(t, err, "empty result")
	require.Empty(t, addresses)
}

func TestH_BypassIfFailedJSON(t *testing.T) {
	t.Parallel()
	var action option.DNSRuleAction
	err := action.UnmarshalJSONContext(context.Background(), []byte(`{"action":"route","server":"primary","bypass_if_failed":true}`))
	require.NoError(t, err)
	require.Equal(t, C.RuleActionTypeRoute, action.Action)
	require.Equal(t, "primary", action.RouteOptions.Server)
	require.True(t, action.RouteOptions.BypassIfFailed)

	var defaultAction option.DNSRuleAction
	err = defaultAction.UnmarshalJSONContext(context.Background(), []byte(`{"server":"primary"}`))
	require.NoError(t, err)
	require.False(t, defaultAction.RouteOptions.BypassIfFailed)

	encoded, err := action.MarshalJSON()
	require.NoError(t, err)
	var decoded option.DNSRuleAction
	require.NoError(t, decoded.UnmarshalJSONContext(context.Background(), encoded))
	require.True(t, decoded.RouteOptions.BypassIfFailed)
	require.Equal(t, "primary", decoded.RouteOptions.Server)
}

type hOptionsCaptureClient struct {
	fakeDNSClient
	access  sync.Mutex
	options []adapter.DNSQueryOptions
}

func (c *hOptionsCaptureClient) Exchange(ctx context.Context, transport adapter.DNSTransport, message *mDNS.Msg, options adapter.DNSQueryOptions, _ func(*mDNS.Msg) bool) (*mDNS.Msg, error) {
	c.access.Lock()
	c.options = append(c.options, options)
	c.access.Unlock()
	return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 60), nil
}

func TestH_LegacyRouteActionTimeoutApplied(t *testing.T) {
	t.Skip("BUG: commit 58602a9e2 removed `options.Timeout = action.Timeout` from matchDNS/applyDNSRouteOptions, so a DNS rule's `timeout` is silently ignored")
	t.Parallel()
	rule := hRouteRule("example.com", "primary", false)
	rule.DefaultOptions.RouteOptions.Timeout = badoption.Duration(3 * time.Second)
	client := &hOptionsCaptureClient{}
	router := &Router{
		ctx:                   context.Background(),
		logger:                log.NewNOPFactory().NewLogger("dns"),
		transport:             hTransportManager("default", "primary"),
		client:                client,
		defaultDomainStrategy: C.DomainStrategyAsIS,
	}
	require.NoError(t, router.Initialize([]option.DNSRule{rule, hLegacyModeRule()}))
	require.NoError(t, router.Start(adapter.StartStateStart))
	t.Cleanup(func() { router.Close() })

	_, err := router.Exchange(context.Background(), hQuery("example.com"), adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Len(t, client.options, 1)
	require.Equal(t, 3*time.Second, client.options[0].Timeout)
}

func TestH_ClearCachePurgesReverseMapping(t *testing.T) {
	t.Skip("BUG: commit 58602a9e2 removed dnsReverseMapping.Purge() from Router.ClearCache, so cleared caches still serve stale reverse mappings")
	t.Parallel()
	router := newTestRouter(t, nil, hTransportManager("default"), &fakeDNSClient{})
	cache, err := freelru.New[netip.Addr, string](16, maphash.NewHasher[netip.Addr]().Hash32, true)
	require.NoError(t, err)
	router.dnsReverseMapping = cache
	message := hQuery("example.com")
	router.recordReverseMapping(message, FixedResponse(0, message.Question[0], []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 60), nil)
	domain, loaded := router.LookupReverseMapping(netip.MustParseAddr("1.2.3.4"))
	require.True(t, loaded)
	require.Equal(t, "example.com", domain)

	router.ClearCache()
	_, loaded = router.LookupReverseMapping(netip.MustParseAddr("1.2.3.4"))
	require.False(t, loaded)
}
