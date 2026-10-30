package awg

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/peerfallback"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// hAnyDialer opens a local UDP socket for any peer, as a detour or the network does.
type hAnyDialer struct{}

func (hAnyDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (hAnyDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

// hStartPathPair starts a server at serverAddress and a client whose only peer is peer, with opts.
func hStartPathPair(t *testing.T, ctx context.Context, serverAddress netip.Prefix, peer func(serverPort uint16) netip.AddrPort, opts DeviceOpts) (*Device, *Device) {
	return hStartPathPairWith(t, ctx, hAnyDialer{}, serverAddress, peer, opts)
}

func hStartPathPairWith(t *testing.T, ctx context.Context, dialer N.Dialer, serverAddress netip.Prefix, peer func(serverPort uint16) netip.AddrPort, opts DeviceOpts) (*Device, *Device) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverPort := hFreeUDPPort(t)
	clientAddress := netip.MustParsePrefix("10.77.0.2/32")
	server, err := NewDevice(ctx, logger.NOP(), &hLoopbackDialer{}, "private_key="+hKeyHex(serverKey)+
		"\nlisten_port="+strconv.Itoa(int(serverPort))+
		"\npublic_key="+hKeyHex(clientKey.PublicKey())+"\nallowed_ip="+clientAddress.String(),
		DeviceOpts{Address: []netip.Prefix{serverAddress}, MTU: 1500})
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	require.NoError(t, server.Start(adapter.StartStateStart))

	opts.Peer = peer(serverPort)
	opts.Address = []netip.Prefix{clientAddress}
	client, err := NewDevice(ctx, logger.NOP(), dialer, "private_key="+hKeyHex(clientKey)+
		"\npublic_key="+hKeyHex(serverKey.PublicKey())+"\nendpoint="+opts.Peer.String()+
		"\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1", opts)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.Start(adapter.StartStateStart))
	return server, client
}

// The client starts on an address where nothing answers, and moves to the fallback one.
func TestH_PathFallback(t *testing.T) {
	wait, interval := peerfallback.Wait, peerfallback.Interval
	peerfallback.Wait, peerfallback.Interval = time.Second, 200*time.Millisecond
	defer func() { peerfallback.Wait, peerfallback.Interval = wait, interval }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serverAddress := netip.MustParsePrefix("10.77.0.1/32")
	dead := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), hFreeUDPPort(t))
	var real netip.AddrPort
	server, client := hStartPathPair(t, ctx, serverAddress, func(serverPort uint16) netip.AddrPort {
		real = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), serverPort)
		return dead
	}, DeviceOpts{MTU: 1408})
	client.path.opts.Fallback = []netip.AddrPort{real}
	client.path.close()
	client.path.start(client) // with the fallback, as NewDevice would set it

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
	}, 15*time.Second, 100*time.Millisecond, "the client never reached the fallback address")
}

// A path that carries only datagrams of up to 1000 bytes: discovery lowers the client's MTU from
// 1408 to what gets through with AmneziaWG's 32 bytes of headers.
func TestH_PathMTUDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var relay *hSizeRelay
	_, client := hStartPathPair(t, ctx, netip.MustParsePrefix("1.1.1.1/32"), func(serverPort uint16) netip.AddrPort {
		relay = hStartSizeRelay(t, serverPort, 1000)
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relay.port())
	}, DeviceOpts{MTU: 1408, MTUDiscovery: true})
	stack := client.tun.(*networkTun).conn
	require.Eventually(t, func() bool { return stack.StackMTU() < 1408 }, 15*time.Second, 50*time.Millisecond)
	require.Equal(t, 960, stack.StackMTU(), "1000 bytes less AmneziaWG's 32, in steps of 16")
}

type hSizeRelay struct{ conn net.PacketConn }

// hStartSizeRelay forwards between a client and the server, dropping datagrams over limit bytes.
func hStartSizeRelay(t *testing.T, serverPort uint16, limit int) *hSizeRelay {
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { packetConn.Close() })
	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(serverPort)}
	go func() {
		var clientAddr net.Addr
		buffer := make([]byte, 65535)
		for {
			n, from, readErr := packetConn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			if n > limit {
				continue
			}
			if from.(*net.UDPAddr).Port == int(serverPort) {
				if clientAddr != nil {
					_, _ = packetConn.WriteTo(buffer[:n], clientAddr)
				}
				continue
			}
			clientAddr = from
			_, _ = packetConn.WriteTo(buffer[:n], serverAddr)
		}
	}()
	return &hSizeRelay{conn: packetConn}
}

func (r *hSizeRelay) port() uint16 {
	return uint16(r.conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestH_PeerPublicKey(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	found, ok := peerPublicKey("private_key=00\npublic_key=" + hKeyHex(key.PublicKey()) + "\nendpoint=1.2.3.4:5")
	require.True(t, ok)
	require.Equal(t, [32]byte(key.PublicKey()), [32]byte(found))
	_, ok = peerPublicKey("public_key=" + hKeyHex(key.PublicKey()) + "\npublic_key=" + hKeyHex(key.PublicKey()))
	require.False(t, ok, "two peers")
}
