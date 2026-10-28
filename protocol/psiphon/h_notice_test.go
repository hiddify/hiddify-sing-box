package psiphon

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// A Tunnels notice carries its count as a JSON number; anything else is not a count, where the
// type assertion it replaced panicked.
func TestH_NoticeCount(t *testing.T) {
	for _, test := range []struct {
		data  map[string]interface{}
		count float64
		ok    bool
	}{
		{map[string]interface{}{"count": float64(2)}, 2, true},
		{map[string]interface{}{"count": 3}, 3, true},
		{map[string]interface{}{"count": int64(1)}, 1, true},
		{map[string]interface{}{"count": json.Number("4")}, 4, true},
		{map[string]interface{}{"count": "2"}, 0, false},
		{map[string]interface{}{"count": nil}, 0, false},
		{map[string]interface{}{}, 0, false},
		{nil, 0, false},
	} {
		count, ok := noticeCount(test.data)
		require.Equal(t, test.ok, ok, "%v", test.data)
		require.Equal(t, test.count, count, "%v", test.data)
	}
}

// psiphon-tunnel-core has one notice writer for the process. A Psiphon that closes while another
// runs (a reload) must not leave the other deaf: it would never see its Tunnels notice and show
// as connecting with a working tunnel.
func TestH_NoticeHubSurvivesAnotherClose(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	old := &Psiphon{logger: logger, ctx: context.Background()}
	current := &Psiphon{logger: logger, ctx: context.Background()}
	seen := make(chan float64, 4)
	listen := func(p *Psiphon) {
		require.NoError(t, listenNotices(p, func(event NoticeEvent) {
			if event.Type == "Tunnels" {
				if count, ok := noticeCount(event.Data); ok {
					p.setConnected(count > 0)
					if p == current {
						seen <- count
					}
				}
			}
		}))
	}
	listen(old)
	listen(current)
	old.Close() // the old box closes after the new one started

	psiphon.NoticeTunnels(1)
	select {
	case count := <-seen:
		require.Equal(t, float64(1), count)
	case <-time.After(2 * time.Second):
		t.Fatal("the running instance no longer gets notices")
	}
	require.True(t, current.connected.Load())

	stopListeningNotices(current)
	noticeHub.access.Lock()
	require.False(t, noticeHub.installed, "the writer is reset with the last instance")
	noticeHub.access.Unlock()
}
