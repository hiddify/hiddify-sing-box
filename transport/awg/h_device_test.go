package awg

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type hLoopbackDialer struct {
	access sync.Mutex
	listen []netip.AddrPort
	conns  []net.PacketConn
}

func (d *hLoopbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, syscall.EAFNOSUPPORT
}

func (d *hLoopbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	defer d.access.Unlock()
	d.listen = append(d.listen, destination.AddrPort())
	if destination.Addr.Is6() {
		return nil, syscall.EAFNOSUPPORT
	}
	packetConn, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(destination.Port))))
	if err != nil {
		return nil, err
	}
	d.conns = append(d.conns, packetConn)
	return packetConn, nil
}

func (d *hLoopbackDialer) boundPort(t *testing.T) uint16 {
	d.access.Lock()
	defer d.access.Unlock()
	require.NotEmpty(t, d.conns)
	return uint16(d.conns[0].LocalAddr().(*net.UDPAddr).Port)
}

var _ N.Dialer = (*hLoopbackDialer)(nil)

func hKeyHex(key wgtypes.Key) string {
	return hex.EncodeToString(key[:])
}

func hFreeUDPPort(t *testing.T) uint16 {
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := packetConn.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, packetConn.Close())
	return uint16(port)
}

func TestH_BindOpenSendReceive(t *testing.T) {
	dialer := &hLoopbackDialer{}
	b := newBind(context.Background(), dialer)
	fns, port, err := b.Open(0)
	require.NoError(t, err)
	require.Equal(t, uint16(0), port)
	require.Len(t, fns, 1, "ipv6 EAFNOSUPPORT must be tolerated")
	require.Len(t, dialer.listen, 2)
	require.True(t, dialer.listen[0].Addr().Is4() && dialer.listen[0].Addr().IsUnspecified())
	require.True(t, dialer.listen[1].Addr().Is6() && dialer.listen[1].Addr().IsUnspecified())

	_, _, err = b.Open(0)
	require.ErrorIs(t, err, conn.ErrBindAlreadyOpen)
	require.Equal(t, 1, b.BatchSize())
	require.NoError(t, b.SetMark(1))

	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	ep, err := b.ParseEndpoint(peer.LocalAddr().String())
	require.NoError(t, err)
	require.Equal(t, peer.LocalAddr().String(), ep.DstToString())
	require.Equal(t, "", ep.SrcToString())
	require.False(t, ep.SrcIP().IsValid())

	require.NoError(t, b.Send([][]byte{[]byte("hello"), []byte("world")}, ep))
	buffer := make([]byte, 64)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, from, err := peer.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buffer[:n]))
	n, _, err = peer.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, "world", string(buffer[:n]))
	require.Equal(t, dialer.boundPort(t), uint16(from.(*net.UDPAddr).Port))

	_, err = peer.WriteTo([]byte("reply"), from)
	require.NoError(t, err)
	packets := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	count, err := fns[0](packets, sizes, eps)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, "reply", string(packets[0][:sizes[0]]))
	require.Equal(t, peer.LocalAddr().String(), eps[0].DstToString())

	v6Endpoint, err := b.ParseEndpoint("[::1]:51820")
	require.NoError(t, err)
	require.Error(t, b.Send([][]byte{[]byte("x")}, v6Endpoint), "no ipv6 socket")

	_, err = b.ParseEndpoint("not-an-endpoint")
	require.Error(t, err)

	require.NoError(t, b.Close())
	require.NoError(t, b.Close())
	_, err = fns[0](packets, sizes, eps)
	require.Error(t, err)

	_, _, err = b.Open(0)
	require.NoError(t, err, "bind must be reopenable after close")
	require.NoError(t, b.Close())
}

func TestH_BindEndpointBytes(t *testing.T) {
	ep := bind_endpoint{AddrPort: netip.MustParseAddrPort("192.0.2.1:51820")}
	expected, err := netip.MustParseAddrPort("192.0.2.1:51820").MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, expected, ep.DstToBytes())
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), ep.DstIP())
}

const hObfuscation = "\njc=3\njmin=10\njmax=40\ns1=15\ns2=20\nh1=1234567\nh2=2345678\nh3=3456789\nh4=4567890"

func hStartTunnelPair(t *testing.T, ctx context.Context, obfuscation string) (*Device, *Device, netip.Prefix) {
	return hStartTunnelPairWithRelay(t, ctx, obfuscation, nil)
}

func hStartTunnelPairWithRelay(t *testing.T, ctx context.Context, obfuscation string, relay func(serverPort uint16) uint16) (*Device, *Device, netip.Prefix) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverPort := hFreeUDPPort(t)
	endpointPort := serverPort
	if relay != nil {
		endpointPort = relay(serverPort)
	}
	serverAddress := netip.MustParsePrefix("10.77.0.1/32")
	clientAddress := netip.MustParsePrefix("10.77.0.2/32")

	serverIpc := "private_key=" + hKeyHex(serverKey) +
		"\nlisten_port=" + strconv.Itoa(int(serverPort)) + obfuscation +
		"\npublic_key=" + hKeyHex(clientKey.PublicKey()) +
		"\nallowed_ip=" + clientAddress.String()
	clientIpc := "private_key=" + hKeyHex(clientKey) + obfuscation +
		"\npublic_key=" + hKeyHex(serverKey.PublicKey()) +
		"\nendpoint=127.0.0.1:" + strconv.Itoa(int(endpointPort)) +
		"\nallowed_ip=10.77.0.0/24"

	server, err := NewDevice(ctx, logger.NOP(), &hLoopbackDialer{}, serverIpc, DeviceOpts{Address: []netip.Prefix{serverAddress}, MTU: 1408})
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	client, err := NewDevice(ctx, logger.NOP(), &hLoopbackDialer{}, clientIpc, DeviceOpts{Address: []netip.Prefix{clientAddress}, MTU: 1408})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	require.False(t, server.IsUnderLoad())
	require.NoError(t, server.Start(adapter.StartStateInitialize))
	require.Nil(t, server.awgDevice, "non-start stages must be ignored")
	require.NoError(t, server.Start(adapter.StartStateStart))
	require.NoError(t, client.Start(adapter.StartStateStart))

	listener, err := server.tun.(*networkTun).conn.ListenTCPAddrPort(netip.AddrPortFrom(serverAddress.Addr(), 8080))
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return server, client, serverAddress
}

func TestH_DeviceLoopbackTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, client, serverAddress := hStartTunnelPair(t, ctx, hObfuscation)

	tcpConn, err := client.DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(serverAddress.Addr(), 8080))
	require.NoError(t, err)
	defer tcpConn.Close()
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(10*time.Second)))
	payload := []byte("amneziawg loopback payload")
	_, err = tcpConn.Write(payload)
	require.NoError(t, err)
	echo := make([]byte, len(payload))
	_, err = io.ReadFull(tcpConn, echo)
	require.NoError(t, err)
	require.Equal(t, payload, echo)

	udpServer, err := server.tun.(*networkTun).conn.ListenUDPAddrPort(netip.AddrPortFrom(serverAddress.Addr(), 5353))
	require.NoError(t, err)
	defer udpServer.Close()
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, readErr := udpServer.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = udpServer.WriteTo(buffer[:n], addr)
		}
	}()
	udpConn, err := client.ListenPacket(ctx, M.SocksaddrFrom(serverAddress.Addr(), 5353))
	require.NoError(t, err)
	defer udpConn.Close()
	require.NoError(t, udpConn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = udpConn.WriteTo([]byte("udp ping"), M.SocksaddrFrom(serverAddress.Addr(), 5353).UDPAddr())
	require.NoError(t, err)
	buffer := make([]byte, 64)
	n, _, err := udpConn.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, "udp ping", string(buffer[:n]))
}

type hUDPRelay struct {
	conn    net.PacketConn
	access  sync.Mutex
	packets [][]byte
}

func hStartRelay(t *testing.T, serverPort uint16) *hUDPRelay {
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { packetConn.Close() })
	relay := &hUDPRelay{conn: packetConn}
	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(serverPort)}
	go func() {
		var clientAddr net.Addr
		buffer := make([]byte, 65535)
		for {
			n, from, readErr := packetConn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			if from.(*net.UDPAddr).Port == int(serverPort) {
				if clientAddr != nil {
					_, _ = packetConn.WriteTo(buffer[:n], clientAddr)
				}
				continue
			}
			clientAddr = from
			relay.access.Lock()
			relay.packets = append(relay.packets, append([]byte(nil), buffer[:n]...))
			relay.access.Unlock()
			_, _ = packetConn.WriteTo(buffer[:n], serverAddr)
		}
	}()
	return relay
}

func (r *hUDPRelay) port() uint16 {
	return uint16(r.conn.LocalAddr().(*net.UDPAddr).Port)
}

func (r *hUDPRelay) captured() [][]byte {
	r.access.Lock()
	defer r.access.Unlock()
	return append([][]byte(nil), r.packets...)
}

func TestH_DeviceObfuscationOnWire(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var relay *hUDPRelay
	_, client, serverAddress := hStartTunnelPairWithRelay(t, ctx, hObfuscation, func(serverPort uint16) uint16 {
		relay = hStartRelay(t, serverPort)
		return relay.port()
	})
	tcpConn, err := client.DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(serverAddress.Addr(), 8080))
	require.NoError(t, err)
	tcpConn.Close()

	packets := relay.captured()
	require.GreaterOrEqual(t, len(packets), 4)
	for _, junk := range packets[:3] {
		require.GreaterOrEqual(t, len(junk), 10)
		require.LessOrEqual(t, len(junk), 40)
	}
	initiation := packets[3]
	require.Len(t, initiation, 15+148, "s1 junk must prefix the initiation")
	require.Equal(t, uint32(1234567), binary.LittleEndian.Uint32(initiation[15:19]), "h1 magic header")
}

func TestH_DeviceStartRejectsInvalidIpc(t *testing.T) {
	device, err := NewDevice(context.Background(), logger.NOP(), &hLoopbackDialer{}, "private_key=zz", DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("10.78.0.1/32")},
		MTU:     1280,
	})
	require.NoError(t, err)
	defer device.Close()
	require.ErrorContains(t, device.Start(adapter.StartStateStart), "set ipc config")
}
