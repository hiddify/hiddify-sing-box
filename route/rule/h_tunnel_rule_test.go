package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

const (
	hTunnelUUIDA = "11111111-1111-1111-1111-111111111111"
	hTunnelUUIDB = "22222222-2222-2222-2222-222222222222"
	hTunnelUUIDC = "33333333-3333-3333-3333-333333333333"
)

func TestH_TunnelSourceItem(t *testing.T) {
	t.Parallel()
	item := NewTunnelSourceItem([]string{hTunnelUUIDA})
	require.True(t, item.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDA}))
	require.False(t, item.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDB}))
	require.False(t, item.Match(&adapter.InboundContext{}))
	require.False(t, item.Match(&adapter.InboundContext{TunnelDestination: hTunnelUUIDA}))
	require.Equal(t, "tunnel_source="+hTunnelUUIDA, item.String())

	multi := NewTunnelSourceItem([]string{hTunnelUUIDA, hTunnelUUIDB})
	require.True(t, multi.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDB}))
	require.False(t, multi.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDC}))
	require.Equal(t, "tunnel_source=["+hTunnelUUIDA+" "+hTunnelUUIDB+"]", multi.String())
}

func TestH_TunnelDestinationItem(t *testing.T) {
	t.Parallel()
	item := NewTunnelDestinationItem([]string{hTunnelUUIDA})
	require.True(t, item.Match(&adapter.InboundContext{TunnelDestination: hTunnelUUIDA}))
	require.False(t, item.Match(&adapter.InboundContext{TunnelDestination: hTunnelUUIDB}))
	require.False(t, item.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDA}))
	require.False(t, item.Match(&adapter.InboundContext{}))
	require.Equal(t, "tunnel_destination="+hTunnelUUIDA, item.String())

	multi := NewTunnelDestinationItem([]string{hTunnelUUIDA, hTunnelUUIDB})
	require.True(t, multi.Match(&adapter.InboundContext{TunnelDestination: hTunnelUUIDB}))
	require.Equal(t, "tunnel_destination=["+hTunnelUUIDA+" "+hTunnelUUIDB+"]", multi.String())
}

func TestH_DefaultRuleTunnelMatch(t *testing.T) {
	t.Parallel()
	rule, err := NewRule(context.Background(), log.NewNOPFactory().NewLogger("router"), option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				TunnelSource:      badoption.Listable[string]{hTunnelUUIDA},
				TunnelDestination: badoption.Listable[string]{hTunnelUUIDB, hTunnelUUIDC},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: "tunnel",
				},
			},
		},
	}, false)
	require.NoError(t, err)
	require.True(t, rule.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDA, TunnelDestination: hTunnelUUIDC}))
	require.False(t, rule.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDA}))
	require.False(t, rule.Match(&adapter.InboundContext{TunnelDestination: hTunnelUUIDB}))
	require.False(t, rule.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDB, TunnelDestination: hTunnelUUIDB}))
	require.Contains(t, rule.String(), "tunnel_source="+hTunnelUUIDA)
	require.Contains(t, rule.String(), "tunnel_destination=[")
}

func TestH_DefaultRuleTunnelInvert(t *testing.T) {
	t.Parallel()
	rule, err := NewRule(context.Background(), log.NewNOPFactory().NewLogger("router"), option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				TunnelSource: badoption.Listable[string]{hTunnelUUIDA},
				Invert:       true,
			},
			RuleAction: option.RuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{Outbound: "direct"},
			},
		},
	}, false)
	require.NoError(t, err)
	require.False(t, rule.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDA}))
	require.True(t, rule.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDB}))
}

func TestH_DNSRuleTunnelMatch(t *testing.T) {
	t.Parallel()
	rule, err := NewDNSRule(context.Background(), log.NewNOPFactory().NewLogger("dns"), option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				TunnelSource: badoption.Listable[string]{hTunnelUUIDA},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Server: "default"},
			},
		},
	}, false, false)
	require.NoError(t, err)
	require.True(t, rule.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDA}))
	require.False(t, rule.Match(&adapter.InboundContext{TunnelSource: hTunnelUUIDB}))
}

func TestH_HeadlessRuleTunnelMatch(t *testing.T) {
	t.Parallel()
	rule, err := NewHeadlessRule(context.Background(), option.HeadlessRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			TunnelDestination: badoption.Listable[string]{hTunnelUUIDB},
		},
	})
	require.NoError(t, err)
	require.True(t, rule.Match(&adapter.InboundContext{TunnelDestination: hTunnelUUIDB}))
	require.False(t, rule.Match(&adapter.InboundContext{TunnelDestination: hTunnelUUIDA}))
}

func TestH_RouteActionOverrideTunnelDestination(t *testing.T) {
	t.Parallel()
	action, err := NewRuleAction(context.Background(), log.NewNOPFactory().NewLogger("router"), option.RuleAction{
		Action: C.RuleActionTypeRoute,
		RouteOptions: option.RouteActionOptions{
			Outbound: "tunnel",
			RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{
				OverrideTunnelDestination: hTunnelUUIDB,
			},
		},
	})
	require.NoError(t, err)
	route, ok := action.(*RuleActionRoute)
	require.True(t, ok)
	require.Equal(t, hTunnelUUIDB, route.OverrideTunnelDestination)
	require.Contains(t, route.String(), "override-tunnel-destination="+hTunnelUUIDB)

	optionsAction, err := NewRuleAction(context.Background(), log.NewNOPFactory().NewLogger("router"), option.RuleAction{
		Action: C.RuleActionTypeRouteOptions,
		RouteOptionsOptions: option.RouteOptionsActionOptions{
			OverrideTunnelDestination: hTunnelUUIDC,
		},
	})
	require.NoError(t, err)
	routeOptions, ok := optionsAction.(*RuleActionRouteOptions)
	require.True(t, ok)
	require.Equal(t, hTunnelUUIDC, routeOptions.OverrideTunnelDestination)
	require.Contains(t, routeOptions.String(), "override-tunnel-destination="+hTunnelUUIDC)

	empty := &RuleActionRouteOptions{}
	for _, description := range empty.Descriptions() {
		require.NotContains(t, description, "override-tunnel-destination")
	}
}

func TestH_DNSRuleBypassIfFailed(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().NewLogger("dns")
	newRule := func(bypass bool, action string) adapter.DNSRule {
		rule, err := NewDNSRule(context.Background(), logger, option.DNSRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					Domain: badoption.Listable[string]{"example.com"},
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: action,
					RouteOptions: option.DNSRouteActionOptions{
						Server: "default",
						AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
							BypassIfFailed: bypass,
						},
					},
				},
			},
		}, false, false)
		require.NoError(t, err)
		return rule
	}
	require.True(t, newRule(true, C.RuleActionTypeRoute).BypassIfFailed())
	require.False(t, newRule(false, C.RuleActionTypeRoute).BypassIfFailed())
	require.False(t, newRule(true, C.RuleActionTypeReject).BypassIfFailed())

	logical, err := NewDNSRule(context.Background(), logger, option.DNSRule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalDNSRule{
			RawLogicalDNSRule: option.RawLogicalDNSRule{
				Mode: C.LogicalTypeOr,
				Rules: []option.DNSRule{{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultDNSRule{
						RawDefaultDNSRule: option.RawDefaultDNSRule{
							Domain: badoption.Listable[string]{"example.com"},
						},
					},
				}},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: "default",
					AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
						BypassIfFailed: true,
					},
				},
			},
		},
	}, false, false)
	require.NoError(t, err)
	require.True(t, logical.BypassIfFailed())
}
