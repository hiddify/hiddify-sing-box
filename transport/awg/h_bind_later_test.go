package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// hNotReadyDialer fails its first dials, as a detour that is still starting does.
type hNotReadyDialer struct{ failures atomic.Int32 }

func (d *hNotReadyDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (d *hNotReadyDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d.failures.Add(-1) >= 0 {
		return nil, errors.New("WireGuard is not ready yet")
	}
	return hAnyDialer{}.ListenPacket(ctx, destination)
}

// A detour that is not ready when the device starts: the start succeeds, and the tunnel works once
// the detour does.
func TestH_BindOpenLater(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dialer := &hNotReadyDialer{}
	dialer.failures.Store(2)
	serverAddress := netip.MustParsePrefix("10.77.0.1/32")
	server, client := hStartPathPairWith(t, ctx, dialer, serverAddress, func(serverPort uint16) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), serverPort)
	}, DeviceOpts{MTU: 1408})
	listener, err := server.tun.(*networkTun).conn.ListenTCPAddrPort(netip.AddrPortFrom(serverAddress.Addr(), 8080))
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			c.Close()
		}
	}()
	require.Eventually(t, func() bool {
		dialCtx, dialCancel := context.WithTimeout(ctx, time.Second)
		defer dialCancel()
		conn, err := client.DialContext(dialCtx, N.NetworkTCP, M.SocksaddrFrom(serverAddress.Addr(), 8080))
		if err == nil {
			conn.Close()
		}
		return err == nil
	}, 15*time.Second, 100*time.Millisecond)
}

// Closing the bind ends a receive loop that is still dialing.
func TestH_BindOpenLaterClose(t *testing.T) {
	dialer := &hNotReadyDialer{}
	dialer.failures.Store(1 << 20)
	bind := newBind(context.Background(), dialer, netip.MustParseAddrPort("127.0.0.1:9"), nil).(*bind_adapter)
	fns, _, err := bind.Open(0)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		for {
			n, err := fns[0](make([][]byte, 1), make([]int, 1), make([]conn.Endpoint, 1))
			if err != nil || n > 0 {
				result <- err
				return
			}
		}
	}()
	require.NoError(t, bind.Close())
	select {
	case err := <-result:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(3 * time.Second):
		t.Fatal("the receive loop kept dialing after Close")
	}
}
