package tunnel

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// hTunnel is a tunnel whose other end the test plays: receive hands a frame to the bridge, and
// sent are the frames the bridge sent.
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

func (t *hTunnel) receive(connID uint32, msgType byte, payload []byte) {
	t.access.Lock()
	onData := t.onData
	t.access.Unlock()
	onData(EncodeFrame(connID, msgType, payload))
}

// sentTypes are the message types the bridge sent for connID.
func (t *hTunnel) sentTypes(connID uint32) []byte {
	t.access.Lock()
	defer t.access.Unlock()
	var types []byte
	for _, frame := range t.sent {
		DecodeFrames(frame, func(id uint32, msgType byte, _ []byte) {
			if id == connID {
				types = append(types, msgType)
			}
		})
	}
	return types
}

func hUDPPayload(destination string, data string) []byte {
	return append(append([]byte{byte(len(destination))}, destination...), data...)
}

// A creator's bridge has its handlers from the moment it is made: the first message of a peer
// goes to them. They were set on the bridge after the connect had returned it, so a bridge
// nobody was given (one made on a reconnect, or for a peer that joined a session whose connect
// had timed out) had none and dialed each destination itself, past the router.
func TestH_CreatorBridgeHasItsHandlersFromTheStart(t *testing.T) {
	accepted := make(chan string, 2)
	tunnel := &hTunnel{}
	NewCreatorBridge(tunnel, AcceptHandlers{
		TCP: func(conn net.Conn, destination string) { accepted <- "tcp " + destination },
		UDP: func(conn net.Conn, destination string) { accepted <- "udp " + destination },
	}, log.NewNOPFactory().Logger())

	tunnel.receive(1, MsgConnect, []byte("example.com:443"))
	tunnel.receive(2, MsgUDP, hUDPPayload("1.1.1.1:53", "query"))
	var got []string
	for range 2 {
		select {
		case destination := <-accepted:
			got = append(got, destination)
		case <-time.After(time.Second):
			t.Fatal("a connection did not go to its handler, got only ", got)
		}
	}
	require.ElementsMatch(t, []string{"tcp example.com:443", "udp 1.1.1.1:53"}, got)
	require.Equal(t, []byte{MsgConnectOK}, tunnel.sentTypes(1))
}

// A creator's bridge never dials: what it has no handler for is refused.
func TestH_CreatorBridgeWithoutHandlersRefuses(t *testing.T) {
	tunnel := &hTunnel{}
	bridge := NewCreatorBridge(tunnel, AcceptHandlers{}, log.NewNOPFactory().Logger())
	tunnel.receive(1, MsgConnect, []byte("example.com:443"))
	tunnel.receive(2, MsgUDP, hUDPPayload("1.1.1.1:53", "query"))
	require.Equal(t, []byte{MsgConnectErr}, tunnel.sentTypes(1))
	_, loaded := bridge.conns.Load(uint32(1))
	require.False(t, loaded)
	_, loaded = bridge.udpClients.Load(uint32(2))
	require.False(t, loaded)
}

// Closing a creator's bridge ends the connections that came through it, UDP ones too: those
// were forgotten open, their readers waiting for good.
func TestH_CreatorBridgeCloseEndsItsConnections(t *testing.T) {
	conns := make(chan net.Conn, 2)
	tunnel := &hTunnel{}
	bridge := NewCreatorBridge(tunnel, AcceptHandlers{
		TCP: func(conn net.Conn, destination string) { conns <- conn },
		UDP: func(conn net.Conn, destination string) { conns <- conn },
	}, log.NewNOPFactory().Logger())
	tunnel.receive(1, MsgConnect, []byte("example.com:443"))
	tunnel.receive(2, MsgUDP, hUDPPayload("1.1.1.1:53", ""))
	read := make(chan error, 2)
	for range 2 {
		select {
		case conn := <-conns:
			go func() {
				// the UDP conn has one empty datagram to read first
				for {
					n, err := conn.Read(make([]byte, 16))
					if err != nil || n > 0 {
						read <- err
						return
					}
				}
			}()
		case <-time.After(time.Second):
			t.Fatal("no connection")
		}
	}
	bridge.Close()
	for range 2 {
		select {
		case err := <-read:
			require.ErrorIs(t, err, io.EOF)
		case <-time.After(time.Second):
			t.Fatal("a connection of the closed bridge is still open")
		}
	}
}
