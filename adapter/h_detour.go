package adapter

// maxGroupDepth bounds the walk through nested groups, in case of a cycle.
const maxGroupDepth = 16

// GroupPath is outbound, the member each group on the way selects now for network, and the
// outbound at the end. A group (selector, urltest, fallback, balancer) is always ready itself
// while the member it selected may still be connecting, so what carries the traffic is the end of
// this path. A group that has not picked a member yet ends it.
func GroupPath(outbound Outbound, network string) []Outbound {
	path := []Outbound{outbound}
	for range maxGroupDepth {
		group, isGroup := outbound.(OutboundGroup)
		if !isGroup {
			break
		}
		selected := group.Selected(network)
		if selected == nil {
			break
		}
		outbound = selected
		path = append(path, outbound)
	}
	return path
}

// PathStatus is the status of the first outbound on path that is not ready, with that outbound;
// ready and nil when every one is.
func PathStatus(path []Outbound) (Status, Outbound) {
	for _, outbound := range path {
		if status := outbound.Status(); status != StatusReady {
			return status, outbound
		}
	}
	return StatusReady, nil
}
