package monitoring

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

// maxGroupDepth bounds the walk through nested groups, in case of a cycle.
const maxGroupDepth = 16

// ResolveDetour returns the tag of the outbound that detour sends network traffic through now,
// following the selection of nested groups.
func ResolveDetour(detour adapter.Outbound, network string) string {
	outbound := detour
	for range maxGroupDepth {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		selected := group.Selected(network)
		if selected == nil {
			break
		}
		outbound = selected
	}
	return outbound.Tag()
}

// FollowDetour calls onChange in its own goroutine each time the outbound that a group detour
// resolves to changes, until ctx or done ends. A tunnel that keeps one connection open through
// the detour reconnects then, instead of staying on a member the group has left. It reports
// false, and does nothing, when detour is not a group or there is no monitoring.
func FollowDetour(ctx context.Context, done <-chan struct{}, detour adapter.Outbound, network string, onChange func(from string, to string)) bool {
	if _, isGroup := detour.(adapter.OutboundGroup); !isGroup {
		return false
	}
	monitor := Get(ctx)
	if monitor == nil {
		return false
	}
	events, err := monitor.SubscribeGroup("")
	if err != nil {
		return false
	}
	current := ResolveDetour(detour, network)
	go func() {
		defer monitor.UnsubscribeGroup("", events)
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case _, ok := <-events:
				if !ok {
					return
				}
			}
			next := ResolveDetour(detour, network)
			if next != current {
				previous := current
				current = next
				onChange(previous, next)
			}
		}
	}()
	return true
}
