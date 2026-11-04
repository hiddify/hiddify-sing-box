package monitoring

import (
	"time"

	N "github.com/sagernet/sing/common/network"
)

// PeriodicCycleRunning reports a regular cycle of the schedule in progress (every interval). Its
// results arrive one by one, and a group that took each at once moved its selection many times
// during one cycle, so the balancer keeps the members it uses while they answer and chooses again
// when the cycle ends. Not the first cycle after start, nor one after a network change: then there
// is no selection worth keeping yet, and the groups take each result as it comes (after the
// debounce of the group events).
func (m *OutboundMonitoring) PeriodicCycleRunning() bool {
	return m.cycleRunning.Load() && m.periodicCycle.Load()
}

// CycleStartedAt is when the running cycle started: a result at or after it is of this cycle.
func (m *OutboundMonitoring) CycleStartedAt() time.Time {
	if started, ok := m.cycleStarted.Load().(time.Time); ok {
		return started
	}
	return time.Time{}
}

// endCycle marks the cycle over and tells every group, so a group that held its selection
// during it chooses with all the results.
func (m *OutboundMonitoring) endCycle() {
	m.cycleRunning.Store(false)
	if registry := m.reg(); registry != nil {
		m.emitAllGroupEvents(registry)
	}
}

// emitAllGroupEvents tells every group of registry that something changed.
func (m *OutboundMonitoring) emitAllGroupEvents(registry *monitoringRegistry) {
	tags := make([]string, 0, len(registry.groups))
	for tag := range registry.groups {
		tags = append(tags, tag)
	}
	m.emitGroupEvent(tags)
}

// groupUses reports whether the group sends its connections through member now: its selection,
// or the selection of the group it selects. A member that starts working changes nothing for
// what goes through a group that uses another one; retesting that (the Extra Security hop behind
// the selector) for every member of a large subscription that answered tested it dozens of times
// in the first cycle, and its ping changed every few seconds.
func (m *OutboundMonitoring) groupUses(groupTag, member string) bool {
	state := m.getState(groupTag)
	if state == nil {
		return false
	}
	for _, outbound := range detourPath(state.outbound, N.NetworkTCP)[1:] { // [0] is the group itself
		if outbound.Tag() == member {
			return true
		}
	}
	return false
}
