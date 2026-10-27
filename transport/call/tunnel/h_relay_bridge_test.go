package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

type hTunnel struct{}

func (hTunnel) SendData([]byte)        {}
func (hTunnel) SetOnData(func([]byte)) {}
func (hTunnel) SetOnClose(func())      {}
func (hTunnel) Reconfigure(int, int)   {}

// a creator bridge made on reconnect keeps the inbound's handlers, so connections still go
// through the router instead of being dialed by the bridge itself
func TestH_RelayBridgeInheritHandlers(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	first := NewRelayBridge(hTunnel{}, "creator", 4096, nil, logger)
	accepted := make(chan string, 1)
	first.SetAcceptHandler(func(conn net.Conn, destination string) { accepted <- destination })
	second := NewRelayBridge(hTunnel{}, "creator", 4096, nil, logger)
	second.InheritHandlers(first)
	second.handleCreatorMessage(1, MsgConnect, []byte("example.com:443"))
	select {
	case destination := <-accepted:
		require.Equal(t, "example.com:443", destination)
	case <-time.After(time.Second):
		t.Fatal("the new bridge did not hand the connection to the inbound")
	}
}
