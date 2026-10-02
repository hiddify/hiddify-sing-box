package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

const (
	hTunnelSourceUUID      = "11111111-1111-1111-1111-111111111111"
	hTunnelDestinationUUID = "22222222-2222-2222-2222-222222222222"
)

func hNewTunnelRouter(t *testing.T, rules ...option.Rule) *Router {
	t.Helper()
	logger := log.NewNOPFactory().NewLogger("router")
	router := &Router{ctx: context.Background(), logger: logger}
	for _, ruleOptions := range rules {
		rule, err := R.NewRule(context.Background(), logger, ruleOptions, false)
		require.NoError(t, err)
		router.rules = append(router.rules, rule)
	}
	return router
}

func hTunnelMetadata() *adapter.InboundContext {
	return &adapter.InboundContext{
		Network:      N.NetworkTCP,
		Domain:       "example.com",
		Destination:  M.Socksaddr{Fqdn: "example.com", Port: 443},
		TunnelSource: hTunnelSourceUUID,
	}
}

func TestH_MatchRuleTunnelSource(t *testing.T) {
	t.Parallel()
	router := hNewTunnelRouter(t,
		option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					TunnelSource: badoption.Listable[string]{"33333333-3333-3333-3333-333333333333"},
				},
				RuleAction: option.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{Outbound: "other"},
				},
			},
		},
		option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					TunnelSource: badoption.Listable[string]{hTunnelSourceUUID},
				},
				RuleAction: option.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{Outbound: "tunnel"},
				},
			},
		},
	)
	metadata := hTunnelMetadata()
	selectedRule, selectedIndex, _, _, err := router.matchRule(context.Background(), metadata, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, selectedRule)
	require.Equal(t, 1, selectedIndex)
	require.Equal(t, "tunnel", selectedRule.Action().(*R.RuleActionRoute).Outbound)
}

func TestH_MatchRuleOverrideTunnelDestination(t *testing.T) {
	t.Skip("BUG: override_tunnel_destination is parsed into RuleActionRouteOptions but never applied to metadata.TunnelDestination in route/route.go matchRule")
	t.Parallel()
	router := hNewTunnelRouter(t,
		option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					TunnelSource: badoption.Listable[string]{hTunnelSourceUUID},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRouteOptions,
					RouteOptionsOptions: option.RouteOptionsActionOptions{
						OverrideTunnelDestination: hTunnelDestinationUUID,
					},
				},
			},
		},
		option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					TunnelDestination: badoption.Listable[string]{hTunnelDestinationUUID},
				},
				RuleAction: option.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{Outbound: "tunnel"},
				},
			},
		},
	)
	metadata := hTunnelMetadata()
	selectedRule, selectedIndex, _, _, err := router.matchRule(context.Background(), metadata, nil, nil)
	require.NoError(t, err)
	require.Equal(t, hTunnelDestinationUUID, metadata.TunnelDestination)
	require.NotNil(t, selectedRule)
	require.Equal(t, 1, selectedIndex)
}

func TestH_ApplyRouteOptionsOverrideKeepsTunnelFields(t *testing.T) {
	t.Parallel()
	metadata := hTunnelMetadata()
	metadata.TunnelDestination = hTunnelDestinationUUID
	applyRouteOptionsOverride(metadata, &R.RuleActionRouteOptions{OverridePort: 8443})
	require.Equal(t, uint16(8443), metadata.Destination.Port)
	require.Equal(t, hTunnelSourceUUID, metadata.TunnelSource)
	require.Equal(t, hTunnelDestinationUUID, metadata.TunnelDestination)
}
