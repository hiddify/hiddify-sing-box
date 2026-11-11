package monitoring

import (
	"slices"

	"github.com/sagernet/sing-box/adapter"
)

// With keep top (h_keep_top.go), the lazy outbounds rest but the ones it names (setActive). A
// lazy outbound that rests (is parked) is not in the cycles and no group sees a result of it, so
// nothing dials through it and it is never created; the app still reads its last result from the
// catch-all group, and a test or a connection asked for by its tag works as for any lazy
// outbound. Outbounds that are not lazy never rest: they run whether they are used or not.

// Parked reports whether tag is a lazy outbound that rests.
func (m *OutboundMonitoring) Parked(tag string) bool {
	if !m.parkLazy.Load() {
		return false
	}
	state := m.getState(tag)
	return state != nil && m.parked(tag, state)
}

func (m *OutboundMonitoring) parked(tag string, state *outboundState) bool {
	if !m.parkLazy.Load() {
		return false
	}
	if _, isLazy := state.outbound.(adapter.LazyOutbound); !isLazy {
		return false
	}
	active := m.active.Load()
	if active == nil {
		return true
	}
	_, isActive := (*active)[tag]
	return !isActive
}

// setActive names the lazy outbounds to use; the others rest. One that comes out of rest is
// tested now, by the workers, as many at a time as a cycle tests, and until its result is in, its
// last one counts as a cached one does: the groups can fall back on it and the app shows it as
// waiting. One that goes to rest is closed as soon as no connection uses it, and its connections
// are left to end. Before Start it only names them: the first cycle tests them.
// It returns the ones it took out of rest.
func (m *OutboundMonitoring) setActive(tags []string) []string {
	next := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		next[tag] = struct{}{}
	}
	m.parkAccess.Lock()
	defer m.parkAccess.Unlock()
	previous := m.active.Swap(&next)
	registry := m.reg()
	var woken []string
	changed := false
	for tag, state := range registry.outbounds {
		lazy, isLazy := state.outbound.(adapter.LazyOutbound)
		if !isLazy {
			continue
		}
		_, isActive := next[tag]
		wasActive := false
		if previous != nil {
			_, wasActive = (*previous)[tag]
		}
		switch {
		case isActive && !wasActive:
			state.mu.Lock()
			state.invalid = true
			if state.history.Delay != 0 {
				state.from_cache = true
				state.history.IpInfoFromCache = state.history.IpInfo != nil
			}
			state.mu.Unlock()
			woken = append(woken, tag)
			changed = true
		case !isActive && wasActive:
			go lazy.Unload()
			changed = true
		}
	}
	if !m.started || !changed {
		return woken
	}
	slices.Sort(woken)
	m.logger.Info("MONITORING ", len(next), " lazy outbounds in use, ", len(woken), " of them taken out of rest")
	cycleID := max(m.cycleSeq.Load(), 1)
	for _, tag := range woken {
		m.enqueueTask(&testTask{outboundTag: tag, cycleID: cycleID, reason: "taken out of rest"})
	}
	m.emitAllGroupEvents(registry)
	return woken
}

// TestOutbounds tests the outbounds of tags, in use or at rest, by the workers: as many at a
// time as a cycle tests. For a list the user looks at: a lazy outbound at rest is created for
// its test and closed after it, so a few exist at a time, not all of them.
func (m *OutboundMonitoring) TestOutbounds(tags []string, reason string) {
	if !m.started {
		return
	}
	cycleID := max(m.cycleSeq.Load(), 1)
	for _, tag := range tags {
		if _, isGroup := m.reg().groups[tag]; isGroup {
			continue
		}
		m.enqueueTask(&testTask{outboundTag: tag, cycleID: cycleID, reason: reason})
	}
}
