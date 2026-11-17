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
	"github.com/sagernet/sing-box/hiddify/peerfallback"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// hStallingDialer is a detour whose streams stall: every connection it gives takes a packet and
// never returns from the write, until it is closed. It keeps what it was asked for.
type hStallingDialer struct {
	hLoopbackDialer
	access  sync.Mutex
	asked   []netip.AddrPort
	conns   []*hStalledConn
	writing chan struct{}
}

func (d *hStallingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn := &hStalledConn{closed: make(chan struct{}), writing: d.writing}
	d.access.Lock()
	d.asked = append(d.asked, destination.AddrPort())
	d.conns = append(d.conns, conn)
	d.access.Unlock()
	return conn, nil
}

func (d *hStallingDialer) askedFor(address netip.AddrPort) bool {
	d.access.Lock()
	defer d.access.Unlock()
	for _, asked := range d.asked {
		if asked == address {
			return true
		}
	}
	return false
}

func (d *hStallingDialer) release() {
	d.access.Lock()
	defer d.access.Unlock()
	for _, conn := range d.conns {
		conn.Close()
	}
}

func hStallDevice(t *testing.T, dialer interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}, peer netip.AddrPort, opts DeviceOpts,
) *Device {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	ipc := "private_key=" + hKeyHex(key) +
		"\npublic_key=" + hKeyHex(peerKey.PublicKey()) +
		"\nendpoint=" + peer.String() +
		"\npersistent_keepalive_interval=1" +
		"\nallowed_ip=0.0.0.0/0"
	opts.Address, opts.MTU, opts.Peer = []netip.Prefix{netip.MustParsePrefix("10.78.0.2/32")}, 1408, peer
	device, err := NewDevice(context.Background(), logger.NOP(), dialer, ipc, opts)
	require.NoError(t, err)
	return device
}

// hWithin fails when action has not returned in time.
func hWithin(t *testing.T, what string, action func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		action()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal(what, " waits for the detour")
	}
}

// A detour whose stream stalled holds one packet and nothing else: the device starts, answers a
// status read, connects its bind again and closes. The device sent with its locks held, so the
// first packet the detour did not take held the device for good.
func TestH_StalledSendDoesNotHoldTheDevice(t *testing.T) {
	dialer := &hStallingDialer{writing: make(chan struct{}, 1)}
	defer dialer.release()
	peer := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(int(hFreeUDPPort(t))))
	device := hStallDevice(t, dialer, peer, DeviceOpts{})
	hWithin(t, "the start", func() { require.NoError(t, device.Start(adapter.StartStateStart)) })
	select {
	case <-dialer.writing: // the first handshake is in the detour, which does not take it
	case <-time.After(5 * time.Second):
		t.Fatal("no handshake was sent")
	}
	hWithin(t, "a status read", func() {
		_, err := device.IpcGet()
		require.NoError(t, err)
	})
	hWithin(t, "connecting the bind again", func() { require.NoError(t, device.BindUpdate()) })
	hWithin(t, "the close", func() { device.Close() })
}

// hSilentDialer is a detour that does not answer a dial, nor its cancel.
type hSilentDialer struct {
	hLoopbackDialer
	dialing chan struct{}
	release chan struct{}
}

func (d *hSilentDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	select {
	case d.dialing <- struct{}{}:
	default:
	}
	<-d.release
	return nil, net.ErrClosed
}

// A detour that does not answer the dial holds nothing either: the bind's connection was dialed
// in Open, which the device calls with its locks held.
func TestH_StalledDialDoesNotHoldTheDevice(t *testing.T) {
	dialer := &hSilentDialer{dialing: make(chan struct{}, 1), release: make(chan struct{})}
	defer close(dialer.release)
	peer := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(int(hFreeUDPPort(t))))
	device := hStallDevice(t, dialer, peer, DeviceOpts{})
	hWithin(t, "the start", func() { require.NoError(t, device.Start(adapter.StartStateStart)) })
	select {
	case <-dialer.dialing:
	case <-time.After(5 * time.Second):
		t.Fatal("the bind did not dial")
	}
	hWithin(t, "a status read", func() {
		_, err := device.IpcGet()
		require.NoError(t, err)
	})
	hWithin(t, "connecting the bind again", func() { require.NoError(t, device.BindUpdate()) })
	hWithin(t, "the close", func() { device.Close() })
}

// With a fallback address, as hiddify-core gives every WARP behind a detour: the fallback moves
// to it while the detour is stalled, and the device still closes, with a move on its way or not.
func TestH_DeviceCloseWithStalledDetourAndFallback(t *testing.T) {
	wait, interval := peerfallback.Wait, peerfallback.Interval
	peerfallback.Wait, peerfallback.Interval = 300*time.Millisecond, 50*time.Millisecond
	defer func() { peerfallback.Wait, peerfallback.Interval = wait, interval }()
	dialer := &hStallingDialer{writing: make(chan struct{}, 1)}
	defer dialer.release()
	peer := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(int(hFreeUDPPort(t))))
	fallback := netip.MustParseAddrPort("127.0.0.2:" + strconv.Itoa(int(hFreeUDPPort(t))))
	device := hStallDevice(t, dialer, peer, DeviceOpts{Fallback: []netip.AddrPort{fallback}})
	hWithin(t, "the start", func() { require.NoError(t, device.Start(adapter.StartStateStart)) })
	require.Eventually(t, func() bool { return dialer.askedFor(fallback) }, 10*time.Second, 20*time.Millisecond,
		"the fallback did not move while the detour was stalled")
	hWithin(t, "the close", func() { device.Close() })

	// closed for good: a move that was on its way does not open the bind again
	_, _, err := device.bind.Open(0)
	require.ErrorIs(t, err, net.ErrClosed)
}
