package call

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// an unknown wbstream mode is refused instead of never connecting
func TestH_ConnectWBStreamMode(t *testing.T) {
	_, err := Connect(context.Background(), Config{Platform: "wbstream", Mode: "audio", Role: RoleJoiner, JoinLink: "x"})
	require.ErrorContains(t, err, "unknown wbstream mode")
}

// A creator is not connected without both handlers: its bridges refuse what they have no
// handler for, so it would serve nothing.
func TestH_CreatorNeedsAcceptHandlers(t *testing.T) {
	handler := func(net.Conn, string) {}
	for _, accept := range []tunnel.AcceptHandlers{{}, {TCP: handler}, {UDP: handler}} {
		_, err := Connect(context.Background(), Config{Platform: "vk", Role: RoleCreator, Accept: accept})
		require.ErrorContains(t, err, "accept handlers")
	}
}

type hNoTunnel struct{}

func (hNoTunnel) SendData([]byte)        {}
func (hNoTunnel) SetOnData(func([]byte)) {}
func (hNoTunnel) SetOnClose(func())      {}
func (hNoTunnel) Reconfigure(int, int)   {}

// Closing the bridge leaves the call, once: it closed the relay bridge only, and the session
// went on.
func TestH_BridgeCloseLeavesTheCall(t *testing.T) {
	var left int
	relay := tunnel.NewJoinerBridge(hNoTunnel{}, logger.NOP())
	bridge := NewBridge(relay, func() { left++ })
	require.NoError(t, bridge.Close())
	require.NoError(t, bridge.Close())
	require.Equal(t, 1, left)
	require.True(t, relay.IsClosed())

	// a creator's bridge has no tunnel to dial through
	left = 0
	creator := NewBridge(nil, func() { left++ })
	_, err := creator.DialContext(context.Background(), "example.com:443")
	require.Error(t, err)
	require.NoError(t, creator.Close())
	require.Equal(t, 1, left)
}
