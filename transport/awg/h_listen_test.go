package awg

import (
	"context"
	"io"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A server's listen_port was handed to the outbound's dialer as a destination, and the dialer
// listens on a port of its own: the server listened on a random port, and no client reached it.
// Here the server has the real dialer, and the client dials its listen port.
func TestH_DeviceServerListensOnItsPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverPort := hFreeUDPPort(t)
	serverAddress := netip.MustParsePrefix("10.78.0.1/32")
	clientAddress := netip.MustParsePrefix("10.78.0.2/32")

	serverIpc := "private_key=" + hKeyHex(serverKey) +
		"\nlisten_port=" + strconv.Itoa(int(serverPort)) + hObfuscation +
		"\npublic_key=" + hKeyHex(clientKey.PublicKey()) +
		"\nallowed_ip=" + clientAddress.String()
	clientIpc := "private_key=" + hKeyHex(clientKey) + hObfuscation +
		"\npublic_key=" + hKeyHex(serverKey.PublicKey()) +
		"\nendpoint=127.0.0.1:" + strconv.Itoa(int(serverPort)) +
		"\nallowed_ip=10.78.0.0/24"

	server, err := NewDevice(ctx, logger.NOP(), N.SystemDialer, serverIpc, DeviceOpts{
		Address:    []netip.Prefix{serverAddress},
		MTU:        1408,
		ListenPort: serverPort,
	})
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	client, err := NewDevice(ctx, logger.NOP(), N.SystemDialer, clientIpc, DeviceOpts{Address: []netip.Prefix{clientAddress}, MTU: 1408})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, server.Start(adapter.StartStateStart))
	require.NoError(t, client.Start(adapter.StartStateStart))

	listener, err := server.tun.(*networkTun).conn.ListenTCPAddrPort(netip.AddrPortFrom(serverAddress.Addr(), 8080))
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		c, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	tcpConn, err := client.DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(serverAddress.Addr(), 8080))
	require.NoError(t, err, "the client reaches the server on its listen port")
	defer tcpConn.Close()
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(10*time.Second)))
	payload := []byte("amneziawg server port")
	_, err = tcpConn.Write(payload)
	require.NoError(t, err)
	echo := make([]byte, len(payload))
	_, err = io.ReadFull(tcpConn, echo)
	require.NoError(t, err)
	require.Equal(t, payload, echo)
}
