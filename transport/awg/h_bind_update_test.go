package awg

import (
	"context"
	"io"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func hEcho(t *testing.T, ctx context.Context, client *Device, destination M.Socksaddr) error {
	conn, err := client.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("after the network changed")
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	echo := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, echo); err != nil {
		return err
	}
	require.Equal(t, payload, echo)
	return nil
}

// On a network change the network manager closed the bind's connection (CloseAll), and the
// device sent into a closed socket for good: "use of closed network connection" until restart.
// BindUpdate failed too, on closing the closed connection, before it opened a new one.
func TestH_BindUpdateAfterNetworkClosedConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, client, serverAddress := hStartTunnelPair(t, ctx, hObfuscation)
	destination := M.SocksaddrFrom(serverAddress.Addr(), 8080)
	require.NoError(t, hEcho(t, ctx, client, destination))

	dialer := client.bind.(*bind_adapter).dialer.(*hLoopbackDialer)
	dialer.access.Lock()
	for _, conn := range dialer.conns {
		conn.Close() // what ConnectionManager.CloseAll does
	}
	dialer.access.Unlock()

	require.NoError(t, client.BindUpdate())
	require.NoError(t, hEcho(t, ctx, client, destination))
}
