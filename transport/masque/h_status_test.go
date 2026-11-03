package masque

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_TunnelLastError(t *testing.T) {
	tunnel := &Tunnel{}
	require.NoError(t, tunnel.LastError(), "nothing failed yet")
	err := errors.New("CONNECT-IP refused")
	tunnel.lastError.Store(&err)
	require.EqualError(t, tunnel.LastError(), "CONNECT-IP refused")
	tunnel.lastError.Store(nil)
	require.NoError(t, tunnel.LastError())
}
