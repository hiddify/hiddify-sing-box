package awg

import (
	"context"
	"net/netip"
	"testing"

	transportAwg "github.com/sagernet/sing-box/transport/awg"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// A UDP session through the endpoint can carry a packet to a domain (Chrome's QUIC after a
// FakeIP address maps back to its name). The netstack took it as a *net.UDPAddr and the core
// panicked in gonet.UDPConn.WriteTo (hiddify-app#2569, WARP in AWG mode); such a packet is
// dropped now, and the endpoint answers the address a listen went to, as the WireGuard endpoint
// does.
func TestH_EndpointDropsPacketsToDomains(t *testing.T) {
	device, err := transportAwg.NewDevice(context.Background(), logger.NOP(), hNopDialer{}, "", transportAwg.DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")},
		MTU:     1280,
	})
	require.NoError(t, err)
	defer device.Close()
	endpoint := hTestEndpoint(nil)
	endpoint.Device = device

	destination := M.ParseSocksaddr("203.0.113.9:443")
	conn, address, err := endpoint.ListenPacketWithDestination(context.Background(), destination)
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, destination.Addr, address)

	packetConn := bufio.NewPacketConn(conn)
	require.NotPanics(t, func() {
		require.NoError(t, packetConn.WritePacket(buf.As([]byte("quic")), M.ParseSocksaddr("example.com:443")))
	})
	// packets to IP addresses pass through iponly (TestH_OutboundDropsPacketsToDomains in
	// masque); this device is not started, so nothing drains its netstack to write one here
}
