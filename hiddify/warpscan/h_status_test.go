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
	status.Scanning()
	require.Equal(t, " · 🔍 Scanning...", status.String())
	status.Found(netip.MustParseAddrPort("162.159.192.7:2408"))
	require.Equal(t, " · 🔍 162.159.192.7:2408", status.String())
	status.NotFound()
	require.Equal(t, " · 🔍 Not found", status.String())
}
