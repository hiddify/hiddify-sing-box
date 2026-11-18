package outbound

import "github.com/sagernet/sing-box/adapter"

var _ adapter.InsecureReasoner = (*Manager)(nil)

// InsecureReason is why the outbound, or else the endpoint, tagged tag is not secure. //H
func (m *Manager) InsecureReason(tag string) string {
	m.access.RLock()
	_, found := m.outboundByTag[tag]
	reason := m.insecure[tag]
	m.access.RUnlock()
	if found {
		return reason
	}
	if reasoner, ok := m.endpoint.(adapter.InsecureReasoner); ok {
		return reasoner.InsecureReason(tag)
	}
	return ""
}
