package balancer

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/monitoring"
	N "github.com/sagernet/sing/common/network"
)

// settleWindow is how long after start the first tests may move the selection before the
// connections opened on the provisional choice (the cache, or the first member) are moved
// once. After that, a faster member only takes new connections.
const settleWindow = 30 * time.Second

// defaultTolerance is the lowest-delay tolerance when the option is unset, as in the URL test
// group: a member must be faster by more than this many milliseconds to take the selection.
const defaultTolerance uint16 = 50

// defaultToleranceRatio is the lowest-delay tolerance_ratio when unset: a member must also be
// faster by more than this share of the selected member's delay, so a slow server is not left
// for a few milliseconds and a fast one is not left for a jitter of a tenth.
const defaultToleranceRatio = 0.1

// measuredDelay is a member's delay as measured, without the cache penalty, for the relative
// tolerance; a member without a result counts as timed out.
func measuredDelay(his *adapter.URLTestHistory) uint16 {
	if his == nil || his.Delay == 0 {
		return monitoring.TimeoutDelay
	}
	return his.Delay
}

// switchThreshold is how much faster another member must be than the selected one, with the
// measured delay currentDelay, to take the selection: the larger of the two tolerances.
func switchThreshold(currentDelay uint16, tolerance uint16, ratio float64) uint32 {
	relative := uint32(float64(currentDelay) * ratio)
	if relative > uint32(tolerance) {
		return relative
	}
	return uint32(tolerance)
}

// SelectedThreshold is how much faster another member must be than the selected one, with the
// result his, to take the selection: switchThreshold for a real ping, none for one cached from
// the previous run, which decides nothing. hiddify-core shows a spreading balancer's row by the
// same rule.
func SelectedThreshold(his *adapter.URLTestHistory, tolerance uint16, ratio float64) uint32 {
	if his != nil && his.IsFromCache {
		return 0
	}
	return switchThreshold(measuredDelay(his), tolerance, ratio)
}

// minStay is how long a member that took the selection with a real ping stays while it answers,
// whatever faster result comes in: the first cycle's results arrive one by one, fastest last as
// often as not, and the selection hopped four times in forty seconds, 439 ms to 170 to 112 to 41
// to 18. Now it hops once, to the best known when the stay is over. A pick from the cache does not
// stay: the first real ping that works takes it.
var minStay = 30 * time.Second // a variable for the tests, which switch at once

// Rank orders members by their results, as lowest-delay does: a real ping that works, then a
// cached one (its delay plus a penalty), then TimeoutDelay for none or a failed one.
func Rank(his *adapter.URLTestHistory) uint16 {
	return getModifiedDelay(his)
}

// memberDead says whether a member's last test failed. A member that has no result yet is
// not dead: its connections may be fine, and it is tested soon.
func memberDead(his *adapter.URLTestHistory) bool {
	return his != nil && his.Delay >= monitoring.TimeoutDelay
}

// memberGroup is the interrupt group of the member's connections, so a member that dies closes
// its own connections and no other member's.
func (s *Balancer) memberGroup(tag string) *interrupt.Group {
	if group, loaded := s.members[tag]; loaded {
		return group
	}
	return s.interruptGroup
}

// update gives the strategy the new results, closes the connections of the members that
// died since the last update, and tells monitoring when the selection moved.
func (s *Balancer) update(history map[string]*adapter.URLTestHistory) {
	changed := false
	var cycleRunning bool
	var cycleStart time.Time
	if s.monitor != nil {
		cycleRunning, cycleStart = s.monitor.PeriodicCycleRunning(), s.monitor.CycleStartedAt()
	}
	if !holdsDuringCycle(cycleRunning, cycleStart, s.strategyFn, history) { // see h_cycle_hold.go
		changed = s.strategyFn.UpdateOutboundsInfo(history)
	}
	for tag, group := range s.members {
		dead := memberDead(history[tag])
		if dead && !s.dead[tag] {
			s.logger.Info("member ", tag, " is down, closing its connections")
			group.Interrupt(s.interruptExternalConnections)
		}
		s.dead[tag] = dead
	}
	if changed && s.monitor != nil && signalsSelection(s.Strategy()) {
		s.monitor.SignalChange(s.Tag()) //H: what follows the group learns the new member at once
	}
}

// signalsSelection reports a strategy whose change of members is worth telling monitoring: one
// that sends every connection through one member (lowest-delay), so the groups and the chain hop
// that follow it now use another. A strategy that spreads connections (round robin, the hashing
// strategies, the pool) changes the members it may use with almost every result while a cycle
// runs, and each telling tested its parents (the Extra Security hop) and its next pick again:
// with a large free subscription, dozens of extra tests a minute, and pings that changed every
// few seconds. Their connections move to the next member anyway.
func signalsSelection(strategy string) bool {
	return strategy == StrategyLowestDelay
}

// settle moves, once, the connections of the members the first tests left out: it closes the
// connections of every member the strategy no longer uses. It waits until some member has a
// result of this run; until then there is nothing better to move to.
func (s *Balancer) settle(history map[string]*adapter.URLTestHistory) {
	if s.settled.Load() {
		return
	}
	keep := s.usedMembers(history)
	if keep == nil {
		return
	}
	s.settled.Store(true)
	for tag, group := range s.members {
		if !keep[tag] {
			group.Interrupt(s.interruptExternalConnections)
		}
	}
}

// usedMembers names the members the strategy uses now: the selected one for lowest-delay,
// the members within the acceptable delay otherwise. It is nil while no member has a result
// of this run.
func (s *Balancer) usedMembers(history map[string]*adapter.URLTestHistory) map[string]bool {
	fresh := false
	for _, his := range history {
		if his != nil && !his.IsFromCache && his.Delay > 0 && his.Delay < monitoring.TimeoutDelay {
			fresh = true
			break
		}
	}
	if !fresh {
		return nil
	}
	used := make(map[string]bool, len(s.members))
	if lowest, isLowest := s.strategyFn.(*LowestDelay); isLowest {
		for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
			if selected := lowest.Select(adapter.InboundContext{}, network, false); selected != nil {
				used[selected.Tag()] = true
			}
		}
		return used
	}
	sorted := sortOutboundsByDelay(convertOutbounds(s.availbleOutbounds), history)
	for network, index := range getAcceptableIndex(sorted, history, acceptableRatio(s.options)) {
		for _, member := range sorted[network][:index+1] {
			used[member.Tag()] = true
		}
	}
	return used
}
