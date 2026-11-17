package awg

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
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
	require.NoError(t, device.Start(adapter.StartStateStart)) // its tunnel is made at the start
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
	// packets to IP addresses pass through iponly (TestH_OutboundDropsPacketsToDomains in masque)
}

// hDomainResolver resolves every name to one address.
type hDomainResolver struct {
	adapter.DNSRouter
	address netip.Addr
}

func (r hDomainResolver) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return []netip.Addr{r.address}, nil
}

// A packet connection listened for a domain carries a packet addressed to that domain into the
// tunnel, to the address the domain resolved to: the other half of #2569, where such a packet
// reached the netstack with a domain for an address. Nothing answers here, so what shows that the
// packet went in is the handshake the device starts for it; a packet to another domain is still
// dropped, and starts none.
func TestH_EndpointCarriesPacketsToItsDomain(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0") // where the device sends its handshakes
	require.NoError(t, err)
	defer peer.Close()
	ipc := "private_key=" + hHex(hKey(t)) +
		"\npublic_key=" + hHex(hKey(t).PublicKey()) +
		"\nendpoint=" + peer.LocalAddr().String() +
		"\nallowed_ip=0.0.0.0/0"
	device, err := transportAwg.NewDevice(context.Background(), logger.NOP(), hNopDialer{}, ipc, transportAwg.DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")},
		MTU:     1280,
	})
	require.NoError(t, err)
	defer device.Close()
	require.NoError(t, device.Start(adapter.StartStateStart))
	endpoint := hTestEndpoint(nil)
	endpoint.Device = device
	resolved := netip.MustParseAddr("10.8.0.1")
	endpoint.dnsRouter = hDomainResolver{address: resolved}
	handshakes := func() bool { // a datagram arrives at the peer within a moment
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(700*time.Millisecond)))
		_, _, readErr := peer.ReadFrom(make([]byte, 2048))
		return readErr == nil
	}

	destination := M.ParseSocksaddr("server.example:5353")
	conn, address, err := endpoint.ListenPacketWithDestination(context.Background(), destination)
	require.NoError(t, err)
	require.Equal(t, resolved, address, "the router is told where the packets go")
	require.NoError(t, bufio.NewPacketConn(conn).WritePacket(buf.As([]byte("dropped")), M.ParseSocksaddr("other.example:5353")))
	require.False(t, handshakes(), "a packet to a domain the connection was not listened for went into the tunnel")
	conn.Close()

	listened, err := endpoint.ListenPacket(context.Background(), destination)
	require.NoError(t, err)
	defer listened.Close()
	require.NoError(t, bufio.NewPacketConn(listened).WritePacket(buf.As([]byte("carried")), destination))
	require.True(t, handshakes(), "the packet addressed to the domain did not go into the tunnel")
}
