package dns

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
)

// ipv6ByOutbound is the strategy of a rule naming an outbound in ipv6_by_outbound: ipv4_only,
// which leaves AAAA questions unanswered, while the monitoring knows the outbound (a group: the
// member it leads to) does not carry IPv6, as its connections showed (route option
// ipv6_fallback); the rule's own strategy otherwise, so a client is handed IPv6 addresses only
// where they lead somewhere. An outbound not observed yet changes nothing: its first IPv6
// connections teach, carried over IPv4 when needed. Without the monitoring nothing changes.
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
