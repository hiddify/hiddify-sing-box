package dns

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
)

// ipv6ByOutbound is the strategy of a rule naming an outbound in ipv6_by_outbound: ipv4_only,
// which leaves AAAA questions unanswered, while the monitoring knows the outbound (a group: its
// selected member) cannot carry IPv6; the rule's own strategy otherwise, so a client is handed
// IPv6 addresses only where they lead somewhere. An IPv6-first site through a proxy without
// IPv6 used to get its AAAA answer, connect, and have the connection closed by the proxy.
func (r *Router) ipv6ByOutbound(strategy C.DomainStrategy, outbound string) C.DomainStrategy {
	if outbound == "" {
		return strategy
	}
	capability := service.FromContext[adapter.IPv6Capability](r.ctx)
	if capability == nil {
		return strategy
	}
	if supported, known := capability.OutboundIPv6(outbound); known && !supported {
		return C.DomainStrategyIPv4Only
	}
	return strategy
}
