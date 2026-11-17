package warp

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/common/dialer"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var _ dialer.PacketDialerWithDestination = (*WARPEndpoint)(nil)

// ListenPacketWithDestination passes the question on to the inner endpoint, which answers the
// address a domain destination resolved to (WireGuard, AmneziaWG and MASQUE all do). The router
// asks an endpoint this way when it can, and maps the replies back to the domain itself; WARP
// only had ListenPacket, so the router did not know the address the packets really go to.
func (w *WARPEndpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	inner := w.currentEndpoint()
	if inner == nil {
		return nil, netip.Addr{}, E.New("endpoint not initialized")
	}
	if withDestination, isWithDestination := inner.(dialer.PacketDialerWithDestination); isWithDestination {
		return withDestination.ListenPacketWithDestination(ctx, destination)
	}
	packetConn, err := inner.ListenPacket(ctx, destination)
	return packetConn, netip.Addr{}, err
}
