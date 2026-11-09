package awg

import (
	"context"
	"errors"
	"io"
	"net"
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

func hGenKey(t *testing.T) wgtypes.Key {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}

// hServeEcho echoes TCP on port 8080 of the device's address.
func hServeEcho(t *testing.T, device *Device, address netip.Prefix) {
	listener, err := device.tun.(*networkTun).conn.ListenTCPAddrPort(netip.AddrPortFrom(address.Addr(), 8080))
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
}

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

// hDestinationDialer is a detour whose UDP needs a destination, as an HTTP proxy's: it refuses
// the any-address connections.
type hDestinationDialer struct{ hAnyDialer }

func (d hDestinationDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.Addr.IsUnspecified() {
		return nil, errors.New("destination required")
	}
	return d.hAnyDialer.ListenPacket(ctx, destination)
}

// hiddify-app#2478: the only peer is given by a domain, resolved after the start. Before it is,
// the device starts without a connection (the any-address ones fail on such a detour), and it
// connects to the address SetPeerEndpoint sets, at once.
func TestH_PendingPeerSetLater(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serverKey, clientKey := hGenKey(t), hGenKey(t)
	serverPort := hFreeUDPPort(t)
	serverAddress := netip.MustParsePrefix("10.77.0.1/32")
	clientAddress := netip.MustParsePrefix("10.77.0.2/32")
	server, err := NewDevice(ctx, logger.NOP(), &hLoopbackDialer{}, "private_key="+hKeyHex(serverKey)+
		"\nlisten_port="+strconv.Itoa(int(serverPort))+
		"\npublic_key="+hKeyHex(clientKey.PublicKey())+"\nallowed_ip="+clientAddress.String(),
		DeviceOpts{Address: []netip.Prefix{serverAddress}, MTU: 1408})
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	require.NoError(t, server.Start(adapter.StartStateStart))
	hServeEcho(t, server, serverAddress)

	client, err := NewDevice(ctx, logger.NOP(), hDestinationDialer{}, "private_key="+hKeyHex(clientKey)+
		"\npublic_key="+hKeyHex(serverKey.PublicKey())+"\nallowed_ip=0.0.0.0/0",
		DeviceOpts{Address: []netip.Prefix{clientAddress}, MTU: 1408, PeerPending: true})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.Start(adapter.StartStateStart))

	require.NoError(t, client.SetPeerEndpoint(hKeyHex(serverKey.PublicKey()), netip.MustParseAddrPort("127.0.0.1:"+strconv.Itoa(int(serverPort))), true))
	started := time.Now()
	require.NoError(t, hEcho(t, ctx, client, M.SocksaddrFrom(serverAddress.Addr(), 8080)))
	require.Less(t, time.Since(started), 3*time.Second, "the handshake waited for the retry")
}
