package monitoring

import "time"

// selectedOf is the outbound a group's selection leads to: its selected member, through nested
// groups; "" when nothing is selected yet. A plain outbound is its own selection.
func (m *OutboundMonitoring) selectedOf(tag string) string {
	reg := m.reg()
	for range 8 { // a group leads to its selected member, which may be a group too
		state, ok := reg.outbounds[tag]
		if !ok {
			return ""
		}
		if _, isGroup := reg.groups[tag]; !isGroup {
			return tag
		}
		next := RealTag(state.outbound)
		if next == "" || next == tag {
			return ""
		}
		tag = next
	}
	return ""
}

// recentResult is how long a result of this run spares the selection a test: a group that moved
// to a member on the cycle's result tested it again seconds later, and under load that second
// ping read 2549 ms for a 59 ms member, and the group moved on.
const recentResult = 15 * time.Second

// testSelected tests, before everything else queued, the outbound a group's selection leads to:
// its ping is the one the user is looking at. Not when it was measured in the last recentResult.
func (m *OutboundMonitoring) testSelected(groupTag string) {
	tag := m.selectedOf(groupTag)
	if tag == "" {
		return
	}
	if state := m.getState(tag); state != nil {
		state.mu.Lock()
		recent := state.workedLocked() && time.Since(state.history.Time) < recentResult
		state.mu.Unlock()
		if recent {
			m.logger.Info("MONITORING ", tag, ": not tested again (the selection of ", groupTag, "): measured in the last ", recentResult)
			return
		}
	}
	m.testNow(tag, true, "the selection of "+groupTag)
}

// testSelections tests what every group's selection leads to, ahead of the first cycle: the
// selected proxy's ping shows at once instead of after every member sorted before it.
func (m *OutboundMonitoring) testSelections() {
	for tag := range m.reg().groups {
		m.testSelected(tag)
	}
}
