package warpscan

import (
	"net/netip"
	"testing"

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
