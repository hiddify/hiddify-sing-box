package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The bind makes its connection again when it ends by itself. Only an interface change did
// (BindUpdate): after anything else that ended the connection the device stopped receiving and
// sent into the dead connection for good.
func TestH_BindReconnectsByItself(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, client, serverAddress := hStartTunnelPair(t, ctx, hObfuscation)
	destination := M.SocksaddrFrom(serverAddress.Addr(), 8080)
	require.NoError(t, hEcho(t, ctx, client, destination))

	dialer := client.bind.(*bind_adapter).dialer.(*hLoopbackDialer)
	dialer.access.Lock()
	for _, conn := range dialer.conns {
		conn.Close() // the connection ends, and nobody tells the device
	}
	dialer.access.Unlock()

	require.Eventually(t, func() bool {
		echoCtx, echoCancel := context.WithTimeout(ctx, 3*time.Second)
		defer echoCancel()
		return hEchoErr(echoCtx, client, destination) == nil
	}, 15*time.Second, 200*time.Millisecond, "the bind did not connect again")
}

// hCloseErrorConn is a detour's connection whose Close reports an error of its own.
type hCloseErrorConn struct{ net.PacketConn }

func (c hCloseErrorConn) Close() error {
	c.PacketConn.Close()
	return errors.New("detour: session already gone")
}

type hCloseErrorDialer struct{ hLoopbackDialer }

func (d *hCloseErrorDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := d.hLoopbackDialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return hCloseErrorConn{conn}, nil
}

// An error of closing a connection does not keep the bind closed: the device stops at an error
// of the bind's Close before it opens the bind again, so BindUpdate left the tunnel down.
func TestH_BindCloseErrorDoesNotKeepItClosed(t *testing.T) {
	peer := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(int(hFreeUDPPort(t))))
	bind := newBind(context.Background(), &hCloseErrorDialer{}, peer, nil).(*bind_adapter)
	for range 2 {
		fns, _, err := bind.Open(0)
		require.NoError(t, err)
		go fns[0]([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1))
		require.Eventually(t, func() bool {
			bind.mutex.Lock()
			defer bind.mutex.Unlock()
			return bind.conn4 != nil
		}, 3*time.Second, 5*time.Millisecond)
		require.NoError(t, bind.Close(), "the close error of a connection is not the bind's")
	}
}
