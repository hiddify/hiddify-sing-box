package adapter_test

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

func TestH_StatusMarks(t *testing.T) {
	require.Empty(t, adapter.StatusReady.Mark())
	for status, text := range map[adapter.Status]string{
		adapter.StatusConnecting:   "Connecting...",
		adapter.StatusReconnecting: "Reconnecting...",
		adapter.StatusSearching:    "🔍 Searching...",
		adapter.StatusFailed:       "❌ Failed",
		adapter.StatusRegistering:  "🔑 Registering...",
	} {
		mark := status.Mark()
		require.Contains(t, mark, text, status.String())
		base, got := adapter.SplitStatus("WARP · WG · 🔍 1.1.1.1:2408" + mark)
		require.Equal(t, "WARP · WG · 🔍 1.1.1.1:2408", base, status.String())
		require.Equal(t, mark[1:], got, status.String())
	}
	base, mark := adapter.SplitStatus("WARP · WG")
	require.Equal(t, "WARP · WG", base)
	require.Empty(t, mark)
}

func TestH_StatusHourglassFlips(t *testing.T) {
	marks := map[string]bool{}
	for _, hourglass := range adapter.HourglassFlip {
		base, _ := adapter.SplitStatus("SSH " + hourglass + " Connecting...")
		require.Equal(t, "SSH", base, "both frames are recognised")
		marks[hourglass] = true
	}
	require.Len(t, marks, 2)
}

func TestH_StatusTracker(t *testing.T) {
	var tracker adapter.StatusTracker
	require.Equal(t, adapter.StatusConnecting, tracker.Status(false), "never connected")
	require.Equal(t, adapter.StatusReady, tracker.Status(true))
	require.Equal(t, adapter.StatusReconnecting, tracker.Status(false), "lost the connection")
	require.Equal(t, adapter.StatusReady, tracker.Status(true))
}
