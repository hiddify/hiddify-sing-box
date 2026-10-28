package warpscan

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_StatusDisplayType(t *testing.T) {
	var status Status
	require.Equal(t, "WARP · WG", DisplayType("WARP · WG", &status, true, " (connecting)"), "no scan yet")
	require.Equal(t, "WARP · WG (connecting)", DisplayType("WARP · WG", nil, false, " (connecting)"))
	status.Scanning()
	require.Equal(t, "WARP · WG · 🔍 Scanning... (connecting)", DisplayType("WARP · WG", &status, false, " (connecting)"))
	status.Found(netip.MustParseAddrPort("162.159.192.7:2408"))
	require.Equal(t, "WARP · WG · 🔍 162.159.192.7:2408", DisplayType("WARP · WG", &status, true, " (connecting)"))
	status.NotFound()
	require.Equal(t, "WARP · WG · 🔍 Not found", DisplayType("WARP · WG", &status, true, " (connecting)"))
}
