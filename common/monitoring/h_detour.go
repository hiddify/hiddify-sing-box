package monitoring

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// maxGroupDepth bounds the walk through nested groups, in case of a cycle.
const maxGroupDepth = 16

// ResolveDetour returns the tag of the outbound that detour sends network traffic through now,
// following the selection of nested groups.
func ResolveDetour(detour adapter.Outbound, network string) string {
	path := detourPath(detour, network)
	return path[len(path)-1].Tag()
}

// detourPath is detour, the member each group on the way selects, and the outbound at the end.
func detourPath(detour adapter.Outbound, network string) []adapter.Outbound {
	path := []adapter.Outbound{detour}
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
		path = append(path, outbound)
	}
	return path
}

// DetourChange is a move of a group detour from one outbound to another.
type DetourChange struct {
	From string
	To   string
	// Automatic is set when the group that moved chose by itself (a URL test, a balancer, a
	// fallback), not a selector set by the user.
	Automatic bool
	// FromFailed is set when the outbound left had failed its last test.
	FromFailed bool
}

// manualGroup is a group whose member the user sets (a selector).
type manualGroup interface {
	SelectOutbound(tag string) bool
}

// FollowDetour calls onChange in its own goroutine each time the outbound that a group detour
// resolves to changes, until ctx or done ends. A tunnel that keeps one connection open through
// the detour reconnects then, instead of staying on a member the group has left. It reports
// false, and does nothing, when detour is not a group or there is no monitoring.
func FollowDetour(ctx context.Context, done <-chan struct{}, detour adapter.Outbound, network string, onChange func(change DetourChange)) bool {
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
	current := detourPath(detour, network)
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
			next := detourPath(detour, network)
			if change, moved := detourMove(monitor, current, next); moved {
				current = next
				onChange(change)
			}
		}
	}()
	return true
}

// detourMove compares two resolutions of a detour: the first group whose member differs is the
// one that moved.
func detourMove(monitor *OutboundMonitoring, previous, next []adapter.Outbound) (DetourChange, bool) {
	from, to := previous[len(previous)-1].Tag(), next[len(next)-1].Tag()
	if from == to {
		return DetourChange{}, false
	}
	change := DetourChange{From: from, To: to}
	for i := 1; i < len(previous) && i < len(next); i++ {
		if previous[i].Tag() != next[i].Tag() {
			_, manual := next[i-1].(manualGroup)
			change.Automatic = !manual
			break
		}
	}
	if monitor != nil {
		if history := monitor.getUrlTest(from); history != nil && history.Delay >= TimeoutDelay {
			change.FromFailed = true
		}
	}
	return change, true
}

// FollowDetourSettled is FollowDetour for a tunnel that is costly to move: a move the user made
// is passed at once, while a move a group made by itself is passed at most once every settle
// (moves in between are joined, and dropped when the group came back), unless the outbound
// left had failed or urgent reports that the tunnel does not work now.
func FollowDetourSettled(ctx context.Context, done <-chan struct{}, detour adapter.Outbound, network string, settle time.Duration, urgent func() bool, onChange func(change DetourChange)) bool {
	if _, isGroup := detour.(adapter.OutboundGroup); !isGroup || Get(ctx) == nil {
		return false
	}
	return FollowDetour(ctx, done, detour, network, settleMoves(ctx, done, settle, urgent, onChange))
}

// settleMoves returns the function that takes the moves of FollowDetourSettled, and passes them
// on to onChange in a goroutine of its own, until ctx or done ends.
func settleMoves(ctx context.Context, done <-chan struct{}, settle time.Duration, urgent func() bool, onChange func(change DetourChange)) func(change DetourChange) {
	var (
		access  sync.Mutex
		pending *DetourChange
	)
	wake := make(chan struct{}, 1)
	go func() {
		lastMove := time.Now() // the tunnel was just opened through the detour
		timer := time.NewTimer(settle)
		timer.Stop()
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-wake:
			case <-timer.C:
			}
			access.Lock()
			change := pending
			if change == nil {
				access.Unlock()
				continue
			}
			if change.From == change.To {
				pending = nil // the group came back
				access.Unlock()
				continue
			}
			if change.Automatic && !change.FromFailed && time.Since(lastMove) < settle && (urgent == nil || !urgent()) {
				access.Unlock()
				timer.Reset(settle - time.Since(lastMove))
				continue
			}
			pending = nil
			access.Unlock()
			lastMove = time.Now()
			onChange(*change)
		}
	}()
	return func(change DetourChange) {
		access.Lock()
		if pending != nil {
			change.From = pending.From // joined: from where the tunnel is
			change.Automatic = change.Automatic && pending.Automatic
			change.FromFailed = change.FromFailed || pending.FromFailed
		}
		pending = &change
		access.Unlock()
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
