package warp

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// hInnerEndpoint is an inner endpoint that answers the address a destination resolved to.
type hInnerEndpoint struct {
	adapter.Endpoint
	resolved netip.Addr
	asked    []M.Socksaddr
}

func (e *hInnerEndpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	e.asked = append(e.asked, destination)
	return nil, e.resolved, nil
}

// hPlainEndpoint is an inner endpoint that only listens.
type hPlainEndpoint struct {
	adapter.Endpoint
	asked []M.Socksaddr
}

func (e *hPlainEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	e.asked = append(e.asked, destination)
	return nil, nil
}

// The router asks WARP for a packet connection with the address its destination resolved to,
// as it asks a WireGuard endpoint, and WARP passes the inner endpoint's answer on.
func TestH_WARPListenPacketWithDestination(t *testing.T) {
	ep := hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON)})
	var asEndpoint adapter.Endpoint = ep
	withDestination, isWithDestination := asEndpoint.(dialer.PacketDialerWithDestination)
	require.True(t, isWithDestination, "the router would only call ListenPacket")
	destination := M.ParseSocksaddr("example.com:443")

	_, _, err := withDestination.ListenPacketWithDestination(context.Background(), destination)
	require.ErrorContains(t, err, "endpoint not initialized")

	inner := &hInnerEndpoint{resolved: netip.MustParseAddr("203.0.113.9")}
	ep.endpoint = inner
	_, address, err := withDestination.ListenPacketWithDestination(context.Background(), destination)
	require.NoError(t, err)
	require.Equal(t, inner.resolved, address)
	require.Equal(t, []M.Socksaddr{destination}, inner.asked)

	plain := &hPlainEndpoint{}
	ep.endpoint = plain
	_, address, err = withDestination.ListenPacketWithDestination(context.Background(), destination)
	require.NoError(t, err)
	require.False(t, address.IsValid())
	require.Equal(t, []M.Socksaddr{destination}, plain.asked)
}
