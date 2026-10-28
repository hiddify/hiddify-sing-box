package awg

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// hStalledConn is a detour whose stream stalled: a write blocks until the connection closes.
type hStalledConn struct {
	net.PacketConn
	closeOnce sync.Once
	closed    chan struct{}
	writing   chan struct{}
}

func (c *hStalledConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case c.writing <- struct{}{}:
	default:
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *hStalledConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *hStalledConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type hStalledDialer struct {
	hLoopbackDialer
	conn *hStalledConn
}

func (d *hStalledDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.conn, nil
}

// A send stuck on a stalled detour held the device's network lock, and Close, which needs it to
// close the bind, waited for good: the box could not stop.
func TestH_DeviceCloseWithStalledDetour(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peer := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(int(hFreeUDPPort(t))))
	stalled := &hStalledConn{closed: make(chan struct{}), writing: make(chan struct{}, 1)}
	ipc := "private_key=" + hKeyHex(key) +
		"\npublic_key=" + hKeyHex(peerKey.PublicKey()) +
		"\nendpoint=" + peer.String() +
		"\npersistent_keepalive_interval=1" +
		"\nallowed_ip=0.0.0.0/0"
	device, err := NewDevice(context.Background(), logger.NOP(), &hStalledDialer{conn: stalled}, ipc, DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("10.78.0.2/32")}, MTU: 1408, Peer: peer,
	})
	require.NoError(t, err)
	go device.Start(adapter.StartStateStart) // its first keepalive is sent at once, and stalls
	select {
	case <-stalled.writing:
	case <-time.After(5 * time.Second):
		t.Fatal("no handshake was sent")
	}

	closed := make(chan struct{})
	go func() {
		device.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		stalled.Close() // let the test end
		t.Fatal("Close waits for a send stuck on the detour")
	}
}
