package adapter

// IPv6Capability tells whether an outbound can carry IPv6 traffic, as the monitoring found by
// opening a connection to an IPv6 address through it; for a group, its selected member's. known
// is false until the outbound was probed, in this run or one whose results were cached. The
// DNS router and the route use it: see dns rule ipv6_by_outbound and rule ipv6_unavailable_via.
type IPv6Capability interface {
	OutboundIPv6(tag string) (supported bool, known bool)
}
