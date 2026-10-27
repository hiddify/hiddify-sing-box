package wireguard

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// hHangingDialer dials until its context ends, like a detour through a dead proxy.
type hHangingDialer struct{}

func (hHangingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (hHangingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// The bind's dial holds the lock that sending and receiving wait on, so a detour that hangs must
// not hold it for good: the dial gives up after the TCP timeout and the next attempt retries.
func TestH_ClientBindConnectGivesUp(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the TCP timeout")
	}
	t.Parallel()
	bind := NewClientBind(context.Background(), logger.NOP(), hHangingDialer{}, true, netip.MustParseAddrPort("127.0.0.1:51820"), [3]uint8{})
	_, _, err := bind.Open(0)
	require.NoError(t, err)
	defer bind.Close()
	result := make(chan error, 1)
	go func() {
		_, err := bind.connect()
		result <- err
	}()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(C.TCPTimeout + 5*time.Second):
		t.Fatal("the bind's dial outlived the TCP timeout")
	}
}
