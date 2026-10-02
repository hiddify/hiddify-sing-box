package endpoint

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestH_AdapterDisplayTypeAndReady(t *testing.T) {
	t.Parallel()
	for proxyType, expected := range map[string]string{
		C.TypeWARP:         "WARP",
		C.TypeAwg:          "Awg",
		C.TypeTunnelServer: "Tunnel Server",
		C.TypeWireGuard:    "WireGuard",
		"unknown-type":     "Unknown",
	} {
		adapter := NewAdapter(proxyType, "tag", nil, nil)
		require.Equal(t, proxyType, adapter.Type())
		require.Equal(t, expected, adapter.DisplayType())
		require.True(t, adapter.IsReady())
	}
}
