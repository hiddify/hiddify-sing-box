package adapter_test

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

func TestH_StatusString(t *testing.T) {
	for status, text := range map[adapter.Status]string{
		adapter.StatusReady:        "ready",
		adapter.StatusConnecting:   "connecting",
		adapter.StatusReconnecting: "reconnecting",
		adapter.StatusSearching:    "searching",
		adapter.StatusFailed:       "failed",
		adapter.StatusRegistering:  "registering",
	} {
		require.Equal(t, text, status.String())
	}
}

func TestH_StatusTracker(t *testing.T) {
	var tracker adapter.StatusTracker
	require.Equal(t, adapter.StatusConnecting, tracker.Status(false), "never connected")
	require.Equal(t, adapter.StatusReady, tracker.Status(true))
	require.Equal(t, adapter.StatusReconnecting, tracker.Status(false), "lost the connection")
	require.Equal(t, adapter.StatusReady, tracker.Status(true))
}
