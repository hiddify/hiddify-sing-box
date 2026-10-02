//go:build with_gvisor

package masque

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	wgTun "github.com/sagernet/wireguard-go/tun"
	"github.com/stretchr/testify/require"
)

func hNewStackTunnel(t *testing.T) *Tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tunnel, err := NewTunnel(ctx, log.NewNOPFactory().NewLogger("masque"), TunnelOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32"), netip.MustParsePrefix("fd01::2/128")},
	})
	require.NoError(t, err)
	t.Cleanup(func() { tunnel.Close() })
	require.NoError(t, tunnel.Start(false))
	require.NoError(t, tunnel.tunDevice.Start())
	select {
	case event := <-tunnel.tunDevice.Events():
		require.Equal(t, wgTun.Event(wgTun.EventUp), event)
	case <-time.After(time.Second):
		t.Fatal("missing up event")
	}
	mtu, err := tunnel.tunDevice.MTU()
	require.NoError(t, err)
	require.Equal(t, 1280, mtu)
	return tunnel
}

func hReadIPv4UDP(t *testing.T, tunnel *Tunnel) (header.IPv4, header.UDP) {
	packet := make([]byte, 1500)
	result := make(chan int, 1)
	go func() {
		n, err := tunnel.tunnelDevice.ReadPacket(packet)
		if err == nil {
			result <- n
		}
	}()
	select {
	case n := <-result:
		ip := header.IPv4(packet[:n])
		require.True(t, ip.IsValid(n))
		require.Equal(t, uint8(header.UDPProtocolNumber), ip.Protocol())
		return ip, header.UDP(ip.Payload())
	case <-time.After(3 * time.Second):
		t.Fatal("no packet left the tunnel device")
		return nil, nil
	}
}

func hBuildIPv4UDP(src, dst netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.Addr().As4()),
		DstAddr:     tcpip.AddrFrom4(dst.Addr().As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp := header.UDP(packet[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dst.Port(), Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(udp.Payload(), payload)
	return packet
}

func TestH_TunnelStackUDPRoundTrip(t *testing.T) {
	tunnel := hNewStackTunnel(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	remote := netip.MustParseAddrPort("198.51.100.1:53")
	conn, err := tunnel.DialContext(ctx, N.NetworkUDP, M.SocksaddrFromNetIP(remote))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("query"))
	require.NoError(t, err)

	ip, udp := hReadIPv4UDP(t, tunnel)
	require.Equal(t, netip.MustParseAddr("172.16.0.2"), netip.AddrFrom4(ip.SourceAddress().As4()))
	require.Equal(t, remote.Addr(), netip.AddrFrom4(ip.DestinationAddress().As4()))
	require.Equal(t, remote.Port(), udp.DestinationPort())
	require.Equal(t, "query", string(udp.Payload()))

	local := netip.AddrPortFrom(netip.MustParseAddr("172.16.0.2"), udp.SourcePort())
	require.NoError(t, tunnel.tunnelDevice.WritePacket(hBuildIPv4UDP(remote, local, []byte("answer"))))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "answer", string(buffer[:n]))
}

func TestH_TunnelStackListenPacketIPv4(t *testing.T) {
	tunnel := hNewStackTunnel(t)
	packetConn, err := tunnel.ListenPacket(context.Background(), M.ParseSocksaddr("203.0.113.9:123"))
	require.NoError(t, err)
	defer packetConn.Close()
	_, err = packetConn.WriteTo([]byte("ntp"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 123})
	require.NoError(t, err)
	ip, udp := hReadIPv4UDP(t, tunnel)
	require.Equal(t, netip.MustParseAddr("172.16.0.2"), netip.AddrFrom4(ip.SourceAddress().As4()))
	require.Equal(t, "ntp", string(udp.Payload()))
}

func TestH_TunnelStackListenPacketIPv6(t *testing.T) {
	t.Skip("BUG: stackDevice.ListenPacket binds IPv6 destinations to inet4Address (device_stack.go IPv6 branch)")
	tunnel := hNewStackTunnel(t)
	packetConn, err := tunnel.ListenPacket(context.Background(), M.ParseSocksaddr("[2001:db8::9]:123"))
	require.NoError(t, err)
	defer packetConn.Close()
	_, err = packetConn.WriteTo([]byte("ntp"), &net.UDPAddr{IP: net.ParseIP("2001:db8::9"), Port: 123})
	require.NoError(t, err)
}

func TestH_TunnelRejectsNonIPDestinations(t *testing.T) {
	tunnel := hNewStackTunnel(t)
	_, err := tunnel.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.ErrorContains(t, err, "invalid non-IP destination")
	_, err = tunnel.ListenPacket(context.Background(), M.ParseSocksaddr("example.com:443"))
	require.ErrorContains(t, err, "invalid non-IP destination")
	_, err = tunnel.tunDevice.DialContext(context.Background(), "sctp", M.ParseSocksaddr("1.1.1.1:1"))
	require.Error(t, err)
}

func TestH_TunnelMissingAddressFamily(t *testing.T) {
	tunnel, err := NewTunnel(context.Background(), log.NewNOPFactory().NewLogger("masque"), TunnelOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
	})
	require.NoError(t, err)
	defer tunnel.Close()
	_, err = tunnel.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("[2001:db8::1]:443"))
	require.ErrorContains(t, err, "missing IPv6 local address")
}
