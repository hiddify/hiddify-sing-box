package edgescan

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

func TestH_StatusString(t *testing.T) {
	var status Status
	require.Empty(t, status.String(), "no scan yet")
	require.Empty(t, (*Status)(nil).String())
	status.Begin()
	require.True(t, status.IsScanning())
	require.Empty(t, status.String(), "the status mark says searching")
	status.Found(netip.MustParseAddrPort("162.159.192.7:2408"))
	require.Equal(t, " · 🔍 162.159.192.7:2408", status.String())
	require.False(t, status.IsScanning())
	status.NotFound()
	require.Equal(t, " · 🔍 Not found", status.String())
}

// MASQUE auto mode scans HTTP/3 and HTTP/2 at once: the one that finds an endpoint wins.
func TestH_StatusOverlappingScans(t *testing.T) {
	var status Status
	h2 := netip.MustParseAddrPort("162.159.198.7:443")
	status.Begin()
	status.Begin()
	status.Found(h2)
	require.False(t, status.IsScanning())
	status.NotFound()
	require.Equal(t, " · 🔍 162.159.198.7:443", status.String(), "the HTTP/3 scan found nothing")

	status.Begin()
	status.Begin()
	status.NotFound()
	require.True(t, status.IsScanning(), "the other scan is still running")
	status.NotFound()
	require.Equal(t, " · 🔍 Not found", status.String())
}

// An exhausted search offers a deep search until one is asked for; the deep search shows while it
// scans, and ends with what it found.
func TestH_StatusDeepSearch(t *testing.T) {
	var status Status
	require.False(t, status.DeepSearchAvailable())
	status.Exhausted(true)
	require.True(t, status.DeepSearchAvailable())
	status.Deep(true)
	require.False(t, status.DeepSearchAvailable(), "it runs")
	status.Begin()
	require.Equal(t, " · 🔍 Deep search", status.String())
	status.Found(netip.MustParseAddrPort("162.159.192.1:2408"))
	status.Exhausted(false)
	status.Deep(false)
	require.False(t, status.DeepSearchAvailable())
	require.Equal(t, " · 🔍 162.159.192.1:2408", status.String())
	require.True(t, status.TryStartDeep())
	require.False(t, status.TryStartDeep(), "started once")
	status.Deep(false) // the deep search ended
	status.Exhausted(true)
	require.True(t, status.DeepSearchAvailable(), "an exhausted deep search offers another")

	// a deep search asked for while a normal one ran is kept when the normal one ends
	require.True(t, status.TryStartDeep())
	status.Exhausted(true)
	require.True(t, status.IsDeep())
	require.False(t, status.DeepSearchAvailable())
}

// The app is told when a deep search is offered and when it no longer is: it learns of it from the
// proxy list, which the monitoring sends again only with its next test, minutes after a search
// gave up.
func TestH_StatusDeepSearchNotifies(t *testing.T) {
	changes, unsubscribe := adapter.SubscribeDeepSearch()
	defer unsubscribe()
	notified := func() bool {
		select {
		case <-changes:
			return true
		case <-time.After(100 * time.Millisecond):
			return false
		}
	}
	var status Status
	status.Exhausted(false)
	require.False(t, notified(), "nothing changed")
	status.Exhausted(true)
	require.True(t, notified(), "a search gave up: offered")
	status.Exhausted(true)
	require.False(t, notified(), "still offered")
	require.True(t, status.TryStartDeep())
	require.True(t, notified(), "a deep search runs: no longer offered")
	status.Exhausted(true)
	require.False(t, notified(), "a deep search asked for keeps the offer away")
	status.Deep(false)
	require.True(t, notified(), "the deep search ended without a find: offered again")
	status.Exhausted(false)
	require.True(t, notified(), "found: no longer offered")
}
