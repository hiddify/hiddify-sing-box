package endpoint

import "github.com/sagernet/sing-box/adapter"

var _ adapter.InsecureReasoner = (*Manager)(nil)

// InsecureReason is why the endpoint tagged tag is not secure. //H
func (m *Manager) InsecureReason(tag string) string {
	m.access.Lock()
	defer m.access.Unlock()
	return m.insecure[tag]
}
