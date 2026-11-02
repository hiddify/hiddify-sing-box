package rule

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

var _ RuleItem = (*IPv6UnavailableItem)(nil)

// IPv6UnavailableItem matches a connection to an IPv6 destination while the monitoring knows the
// named outbound (a group: the member it leads to) does not carry IPv6, as its connections
// showed (route option ipv6_fallback). With a reject action, such a connection is refused at
// once, before its handshake, and the client falls back to IPv4, instead of being accepted by a
// proxy that then closes it, which a browser shows as a dead site. An outbound not observed yet
// never matches: its first IPv6 connections are the ones that teach, carried over IPv4 when
// needed. Without the monitoring it never matches.
type IPv6UnavailableItem struct {
	ctx        context.Context
	outbound   string
	capability adapter.IPv6Capability
}

func NewIPv6UnavailableItem(ctx context.Context, outbound string) *IPv6UnavailableItem {
	return &IPv6UnavailableItem{ctx: ctx, outbound: outbound}
}

func (r *IPv6UnavailableItem) Match(metadata *adapter.InboundContext) bool {
	if !(metadata.IPVersion == 6 || metadata.Destination.IsIP() && metadata.Destination.IsIPv6()) {
		return false
	}
	// the monitoring registers after the rules are made
	if r.capability == nil {
		r.capability = service.FromContext[adapter.IPv6Capability](r.ctx)
		if r.capability == nil {
			return false
		}
	}
	supported, known := r.capability.OutboundIPv6(r.outbound)
	return known && !supported
}

func (r *IPv6UnavailableItem) String() string {
	return "ipv6_unavailable_via=" + r.outbound
}
