package psiphon

import (
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// The tunnel core's ActiveTunnel notice reaches the scanner: before, only Info notices did, so
// the protocol of a tunnel that came up was never rated.
func TestH_PsiphonActiveTunnelReachesScanner(t *testing.T) {
	p := &Psiphon{logger: log.NewNOPFactory().Logger()}
	var seen []string
	p.onInfo = func(event NoticeEvent) { seen = append(seen, event.Type) }
	p.onNotice(NoticeEvent{Type: "ActiveTunnel", Data: map[string]interface{}{"protocol": "OSSH"}}, func() {})
	p.onNotice(NoticeEvent{Type: "Info", Data: map[string]interface{}{"message": "x"}}, func() {})
	p.onNotice(NoticeEvent{Type: "Alert", Data: map[string]interface{}{}}, func() {})
	require.Equal(t, []string{"ActiveTunnel", "Info"}, seen)
}
