package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type hIPv6Capability map[string]bool

func (c hIPv6Capability) OutboundIPv6(tag string) (bool, bool) {
	supported, known := c[tag]
	return supported, known
}

func (c hIPv6Capability) ObserveIPv6(tag string, carried bool) { c[tag] = carried }

// The item matches an IPv6 destination only while the named outbound is known to lack IPv6; an
// IPv4 destination, an outbound with IPv6 and one not observed yet never match.
func TestH_IPv6UnavailableItem(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.IPv6Capability](ctx, hIPv6Capability{"with6": true, "without6": false})
	v6 := &adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::1]:443")}
	v4 := &adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.1:443")}
	byVersion := &adapter.InboundContext{IPVersion: 6}

	without := NewIPv6UnavailableItem(ctx, "without6")
	require.True(t, without.Match(v6))
	require.True(t, without.Match(byVersion))
	require.False(t, without.Match(v4))
	require.Equal(t, "ipv6_unavailable_via=without6", without.String())

	require.False(t, NewIPv6UnavailableItem(ctx, "with6").Match(v6))
	require.False(t, NewIPv6UnavailableItem(ctx, "unknown").Match(v6), "not observed yet: let through, its connections teach")
	require.False(t, NewIPv6UnavailableItem(service.ContextWithDefaultRegistry(context.Background()), "without6").Match(v6), "no monitoring: never matches")
}

type hRulesRouter struct {
	adapter.Router
	rules []adapter.Rule
}

func (r *hRulesRouter) Rules() []adapter.Rule { return r.rules }

type hFinalOutbounds struct {
	adapter.OutboundManager
	final adapter.Outbound
}

func (m *hFinalOutbounds) Default() adapter.Outbound { return m.final }

type hTaggedOutbound struct {
	adapter.Outbound
	tag string
}

func (o *hTaggedOutbound) Tag() string { return o.tag }

func hRouteRule(t *testing.T, ctx context.Context, raw option.RawDefaultRule, action string, outbound string) adapter.Rule {
	t.Helper()
	rule, err := NewRule(ctx, log.NewNOPFactory().NewLogger("router"), option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: raw,
			RuleAction: option.RuleAction{
				Action:        action,
				RouteOptions:  option.RouteActionOptions{Outbound: outbound},
				BypassOptions: option.RouteActionOptions{Outbound: outbound},
			},
		},
	}, false)
	require.NoError(t, err)
	return rule
}

// hiddify-app #2641: the reject rule sits before the sniff and every routing rule, and matched
// every IPv6 connection while the main proxy lacked IPv6, even one the rules send direct, so a
// domestic service's native IPv6 was refused. It matches only what the rules route through the
// named outbound: the final outbound or a rule naming it, never a direct or bypass rule.
func TestH_IPv6UnavailableItemOnlyRoutedVia(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.IPv6Capability](ctx, hIPv6Capability{"select": false, "direct": true})
	router := &hRulesRouter{}
	service.MustRegister[adapter.Router](ctx, router)
	service.MustRegister[adapter.OutboundManager](ctx, &hFinalOutbounds{final: &hTaggedOutbound{tag: "select"}})

	reject := hRouteRule(t, ctx, option.RawDefaultRule{IPVersion: 6, IPv6UnavailableVia: "select"}, C.RuleActionTypeReject, "")
	router.rules = []adapter.Rule{
		reject,
		hRouteRule(t, ctx, option.RawDefaultRule{}, C.RuleActionTypeSniff, ""),
		hRouteRule(t, ctx, option.RawDefaultRule{Port: []uint16{8443}}, C.RuleActionTypeRoute, "direct"),
		hRouteRule(t, ctx, option.RawDefaultRule{Port: []uint16{8444}}, C.RuleActionTypeBypass, ""),
		hRouteRule(t, ctx, option.RawDefaultRule{Port: []uint16{8445}}, C.RuleActionTypeRoute, "select"),
		// a route rule holding the item itself is passed over while looking ahead, not recursed into
		hRouteRule(t, ctx, option.RawDefaultRule{Port: []uint16{8446}, IPv6UnavailableVia: "select"}, C.RuleActionTypeRoute, "direct"),
	}
	v6 := func(port uint16) *adapter.InboundContext {
		return &adapter.InboundContext{IPVersion: 6, Destination: M.ParseSocksaddrHostPort("2001:db8::1", port)}
	}

	require.True(t, reject.Match(v6(443)), "the final outbound is the one without IPv6")
	require.True(t, reject.Match(v6(8445)), "a rule routes it through the one without IPv6")
	require.False(t, reject.Match(v6(8443)), "a rule routes it direct")
	require.False(t, reject.Match(v6(8444)), "a rule bypasses it")
	require.True(t, reject.Match(v6(8446)), "the self-referencing rule says nothing, the final decides")
	require.False(t, reject.Match(&adapter.InboundContext{IPVersion: 4, Destination: M.ParseSocksaddr("192.0.2.1:443")}))

	direct := NewIPv6UnavailableItem(ctx, "direct")
	require.False(t, direct.Match(v6(8443)), "direct carries IPv6")
}
