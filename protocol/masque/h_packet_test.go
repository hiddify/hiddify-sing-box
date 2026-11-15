package masque

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// A UDP session through the outbound can carry a packet to a domain (Chrome's QUIC after a
// FakeIP address maps back to its name). The tunnel's netstack took it as a *net.UDPAddr and the
// core panicked in gonet.UDPConn.WriteTo (hiddify-app#2569); such a packet is dropped now, and
// packets to IP addresses still go out.
func TestH_OutboundDropsPacketsToDomains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := log.NewNOPFactory().NewLogger("masque")
	tunnel, err := masque.NewTunnel(ctx, logger, masque.TunnelOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
	})
	require.NoError(t, err)
	defer tunnel.Close()
	require.NoError(t, tunnel.Start(false))

	ready := make(chan struct{})
	close(ready)
	outbound := &Outbound{logger: logger, tunnel: tunnel, await: ready}
	destination := M.ParseSocksaddr("203.0.113.9:443")
	conn, address, err := outbound.ListenPacketWithDestination(ctx, destination)
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, destination.Addr, address)

	packetConn := bufio.NewPacketConn(conn)
	require.NotPanics(t, func() {
		require.NoError(t, packetConn.WritePacket(buf.As([]byte("quic")), M.ParseSocksaddr("example.com:443")))
	})
	_, err = conn.WriteTo([]byte("quic"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443})
	require.NoError(t, err)
}
