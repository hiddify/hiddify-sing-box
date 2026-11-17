package vk

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// hTunnel is a peer's tunnel whose other end the test plays.
type hTunnel struct {
	access sync.Mutex
	onData func([]byte)
	sent   [][]byte
}

func (t *hTunnel) SendData(data []byte) {
	t.access.Lock()
	t.sent = append(t.sent, data)
	t.access.Unlock()
}

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

func hObfuscator(t *testing.T) *tunnel.TunnelObfuscator {
	obfuscator, err := tunnel.NewTunnelObfuscator([]byte("secret"))
	require.NoError(t, err)
	return obfuscator
}

// The bridge of every peer that connects has the session's handlers: the first one, and one that
// connects later, with nobody having set anything on it. A bridge made after the connect had
// given up, or on a reconnect before the inbound knew of it, dialed past the router.
func TestH_EveryPeerBridgeHasTheSessionsHandlers(t *testing.T) {
	accepted := make(chan string, 1)
	bridge := newBridge(nil, nil, 32768, hObfuscator(t), tunnel.AcceptHandlers{
		TCP: func(conn net.Conn, destination string) { accepted <- destination },
		UDP: func(conn net.Conn, destination string) {},
	}, logger.NOP())
	for _, destination := range []string{"first.example:443", "second.example:443"} {
		peer := &hTunnel{}
		bridge.newRelay().(*TunnelRelay).OnConnected(peer) // as the relay does when a peer's video arrives
		peer.connect(1, destination)
		select {
		case got := <-accepted:
			require.Equal(t, destination, got)
		case <-time.After(time.Second):
			t.Fatal("the connection did not go to the inbound's handler")
		}
	}

	// closing the bridge closes the peer's bridge, and one that comes too late
	bridge.mu.Lock()
	active := bridge.activeBridge
	bridge.mu.Unlock()
	bridge.Close()
	require.True(t, active.IsClosed())
	late := &hTunnel{}
	bridge.newRelay().(*TunnelRelay).OnConnected(late)
	bridge.mu.Lock()
	require.Same(t, active, bridge.activeBridge, "a closed bridge takes no new peer")
	bridge.mu.Unlock()
}

// Closing the bridge ends its joining loop, also while it waits for a server that does not
// answer. The loop had no end, so a connect that gave up left one more session behind each time.
func TestH_ClosedBridgeStopsJoining(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0") // takes the dial's packets and never answers
	require.NoError(t, err)
	defer silent.Close()
	bridge := newBridge(nil, nil, 32768, hObfuscator(t), tunnel.AcceptHandlers{}, logger.NOP())
	done := make(chan struct{})
	go func() {
		bridge.Run(&CallInfo{JoinLink: "https://vk.ru/call/join/token", WtEndpoint: "https://" + silent.LocalAddr().String() + "/ws?x=1"}, "", VKConfig{})
		close(done)
	}()
	time.Sleep(300 * time.Millisecond) // it is dialling by now
	bridge.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge went on after Close")
	}
}
