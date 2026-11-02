package dns

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type hIPv6Capability map[string]bool

func (c hIPv6Capability) OutboundIPv6(tag string) (bool, bool) {
	supported, known := c[tag]
	return supported, known
}

func (c hIPv6Capability) ObserveIPv6(tag string, carried bool) { c[tag] = carried }

// A rule naming an outbound in ipv6_by_outbound answers AAAA unless the outbound is known to lack
// IPv6; one not observed yet keeps the rule's strategy, so its connections can teach. Nothing
// changes without the monitoring.
func TestH_DNSRouterIPv6ByOutbound(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.IPv6Capability](ctx, hIPv6Capability{"with6": true, "without6": false})
	router := &Router{ctx: ctx}
	require.Equal(t, C.DomainStrategyPreferIPv4, router.ipv6ByOutbound(C.DomainStrategyPreferIPv4, ""))
	require.Equal(t, C.DomainStrategyPreferIPv4, router.ipv6ByOutbound(C.DomainStrategyPreferIPv4, "with6"))
	require.Equal(t, C.DomainStrategyPreferIPv4, router.ipv6ByOutbound(C.DomainStrategyPreferIPv4, "unknown"), "not observed yet: its connections teach")
	require.Equal(t, C.DomainStrategyIPv4Only, router.ipv6ByOutbound(C.DomainStrategyPreferIPv4, "without6"))
	require.Equal(t, C.DomainStrategyIPv4Only, router.ipv6ByOutbound(C.DomainStrategyPreferIPv6, "without6"))

	bare := &Router{ctx: service.ContextWithDefaultRegistry(context.Background())}
	require.Equal(t, C.DomainStrategyAsIS, bare.ipv6ByOutbound(C.DomainStrategyAsIS, "without6"), "no monitoring: nothing changes")
}
