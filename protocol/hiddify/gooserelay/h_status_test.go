package gooserelay

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

// The display type has no status; the endpoints once working, and why it failed when none answered.
func TestH_GooseRelayDisplayType(t *testing.T) {
	t.Parallel()
	out, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "goose", option.GooseRelayOptions{
		ScriptKeys: []string{"a", "b"},
		TunnelKey:  "0000000000000000000000000000000000000000000000000000000000000000",
	})
	require.NoError(t, err)
	h := out.(*Outbound)
	require.Equal(t, adapter.StatusConnecting, h.Status())
	require.Equal(t, "GooseRelay", adapter.DisplayType(h))

	h.started = -1
	require.Equal(t, adapter.StatusFailed, h.Status())
	require.Equal(t, "GooseRelay: all 2 endpoints failed the check", adapter.DisplayType(h))

	h.started = 1
	require.NoError(t, adapter.StatusError(h))
	require.Equal(t, "GooseRelay · 2 endpoints", adapter.DisplayType(h))
}
