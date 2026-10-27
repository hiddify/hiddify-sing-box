package warp

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

type hStatusEndpoint struct {
	adapter.Endpoint
	status string
}

func (e *hStatusEndpoint) IpcGet() (string, error) { return e.status, nil }

func TestH_PeerStatus(t *testing.T) {
	lastHandshake, tx := peerStatus(&hStatusEndpoint{status: "private_key=00\npublic_key=11\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\ntx_bytes=1200\nrx_bytes=900\n"})
	require.Equal(t, time.Unix(1700000000, 5), lastHandshake)
	require.Equal(t, uint64(1200), tx)

	lastHandshake, tx = peerStatus(&hStatusEndpoint{status: "public_key=11\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\ntx_bytes=148\n"})
	require.True(t, lastHandshake.IsZero(), "never handshaken")
	require.Equal(t, uint64(148), tx)

	lastHandshake, tx = peerStatus(&hStatusEndpoint{})
	require.True(t, lastHandshake.IsZero())
	require.Zero(t, tx)
}
