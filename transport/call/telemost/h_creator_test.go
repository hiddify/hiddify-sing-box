package telemost

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/call/tunnel"

	"github.com/stretchr/testify/require"
)

// hTunnel is a peer's tunnel whose other end the test plays.
type hTunnel struct {
	access sync.Mutex
	onData func([]byte)
}

func (t *hTunnel) SendData([]byte) {}

func (t *hTunnel) SetOnData(fn func([]byte)) {
	t.access.Lock()
	t.onData = fn
	t.access.Unlock()
}
func (t *hTunnel) SetOnClose(func())    {}
func (t *hTunnel) Reconfigure(int, int) {}

func (t *hTunnel) connect(connID uint32, destination string) {
	t.access.Lock()
	onData := t.onData
	t.access.Unlock()
	onData(tunnel.EncodeFrame(connID, tunnel.MsgConnect, []byte(destination)))
}

// The bridge of every peer that connects has the session's handlers, in every websocket session
// of the bridge, with nobody having set anything on it; closing the bridge closes it.
func TestH_EveryPeerBridgeHasTheSessionsHandlers(t *testing.T) {
	accepted := make(chan string, 1)
	bridge := hBridge(t, nil)
	bridge.accept = tunnel.AcceptHandlers{
		TCP: func(conn net.Conn, destination string) { accepted <- destination },
		UDP: func(conn net.Conn, destination string) {},
	}
	for _, destination := range []string{"first.example:443", "second.example:443"} {
		require.NoError(t, bridge.initRelay()) // a new websocket session
		relay, err := bridge.session()
		require.NoError(t, err)
		peer := &hTunnel{}
		relay.OnConnected(peer) // as the relay does when a peer's video arrives
		peer.connect(1, destination)
		select {
		case got := <-accepted:
			require.Equal(t, destination, got)
		case <-time.After(time.Second):
			t.Fatal("the connection did not go to the inbound's handler")
		}
	}

	active := bridge.getActiveBridge()
	bridge.Close()
	require.True(t, active.IsClosed())
	relay, err := bridge.session()
	require.NoError(t, err)
	relay.OnConnected(&hTunnel{})
	require.Same(t, active, bridge.getActiveBridge(), "a closed bridge takes no new peer")
	relay.Close()
}
