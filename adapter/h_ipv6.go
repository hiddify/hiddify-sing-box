package adapter

// IPv6Capability tells whether an outbound carries IPv6 traffic, as the router learned from the
// connections it carried (route option ipv6_fallback): a connection to an IPv6 address that the
// destination answered says yes; one that got nothing while the same destination answered over
// IPv4 says no. For a group, the member it leads to. known is false until the outbound was
// observed. The DNS router and the route use it: see dns rule ipv6_by_outbound and rule
// ipv6_unavailable_via.
type IPv6Capability interface {
	OutboundIPv6(tag string) (supported bool, known bool)
	// ObserveIPv6 records what a connection to an IPv6 destination through the outbound showed:
	// carried when the destination answered, not carried when it answered over IPv4 instead.
	ObserveIPv6(tag string, carried bool)
}
