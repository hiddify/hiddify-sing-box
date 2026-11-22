package rule

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

var _ RuleItem = (*IPv6UnavailableItem)(nil)

// IPv6UnavailableItem matches a connection to an IPv6 destination that goes through the named
// outbound (a group: the member it leads to) while the monitoring knows that outbound does not
// carry IPv6, as its connections showed (route option ipv6_fallback). With a reject action, such
// a connection is refused at once, before its handshake, and the client falls back to IPv4,
// instead of being accepted by a proxy that then closes it, which a browser shows as a dead
// site. An outbound not observed yet never matches: its first IPv6 connections are the ones that
// teach, carried over IPv4 when needed. Without the monitoring it never matches.
//
// "Goes through" is judged by the route rules on what is known of the connection where the item
// is matched, before its handshake: its address, port, process and any domain the DNS or fake IP
// mapping already gave it, not a sniffed one. A connection the rules send elsewhere (direct, a
// LAN bypass, another outbound) never matches: refusing it would cut IPv6 the device has
// natively, and an app that dials addresses from its own DNS (hiddify-app #2641) never falls
// back. A connection a sniffed domain later sends through the outbound is carried over IPv4 by
// ipv6_fallback instead.
type IPv6UnavailableItem struct {
	ctx        context.Context
	outbound   string
	capability adapter.IPv6Capability
	router     adapter.Router
	outbounds  adapter.OutboundManager
}

func NewIPv6UnavailableItem(ctx context.Context, outbound string) *IPv6UnavailableItem {
	return &IPv6UnavailableItem{ctx: ctx, outbound: outbound}
}

func (r *IPv6UnavailableItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.IPv6RouteLookahead {
		// a route rule holding this item, met while looking ahead: it cannot say yet
		return false
	}
	if !(metadata.IPVersion == 6 || metadata.Destination.IsIP() && metadata.Destination.IsIPv6()) {
		return false
	}
	// the monitoring and the router register after the rules are made
	if r.capability == nil {
		r.capability = service.FromContext[adapter.IPv6Capability](r.ctx)
		if r.capability == nil {
			return false
		}
	}
	supported, known := r.capability.OutboundIPv6(r.outbound)
	if !known || supported {
		return false
	}
	return r.routedVia(metadata)
}

// routedVia says whether the route rules send the connection through the named outbound: the
// first rule with a route or bypass action that matches it decides, else the final outbound.
// Rules with other actions are passed over: a sniff has nothing to read before the handshake, and
// a reject or a DNS hijack before this item's own rule would have ended the match already.
func (r *IPv6UnavailableItem) routedVia(metadata *adapter.InboundContext) bool {
	if r.router == nil {
		r.router = service.FromContext[adapter.Router](r.ctx)
		r.outbounds = service.FromContext[adapter.OutboundManager](r.ctx)
		if r.router == nil {
			// no router to ask (a bare rule): the named outbound is the one it judges
			return true
		}
	}
	lookahead := *metadata
	lookahead.IPv6RouteLookahead = true
	for _, rule := range r.router.Rules() {
		var outbound string
		switch action := rule.Action().(type) {
		case *RuleActionRoute:
			outbound = action.Outbound
		case *RuleActionBypass:
			outbound = action.Outbound
		default:
			continue
		}
		lookahead.ResetRuleCache()
		if rule.Match(&lookahead) {
			return outbound == r.outbound
		}
	}
	if r.outbounds == nil {
		return true
	}
	final := r.outbounds.Default()
	return final != nil && final.Tag() == r.outbound
}

func (r *IPv6UnavailableItem) String() string {
	return "ipv6_unavailable_via=" + r.outbound
}
