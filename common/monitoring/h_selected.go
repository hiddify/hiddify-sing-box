package monitoring

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

// testSelected tests, before everything else queued, the outbound a group's selection leads to:
// its ping is the one the user is looking at.
func (m *OutboundMonitoring) testSelected(groupTag string) {
	if tag := m.selectedOf(groupTag); tag != "" {
		m.testNow(tag, true)
	}
}

// testSelections tests what every group's selection leads to, ahead of the first cycle: the
// selected proxy's ping shows at once instead of after every member sorted before it.
func (m *OutboundMonitoring) testSelections() {
	for tag := range m.reg().groups {
		m.testSelected(tag)
	}
}
