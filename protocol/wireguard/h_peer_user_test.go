package wireguard

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/peeruser"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hPeerUserRouter struct {
	adapter.Router
	metadata adapter.InboundContext
}

func (r *hPeerUserRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	r.metadata = metadata
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (r *hPeerUserRouter) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	r.metadata = metadata
}

// Flows forwarded packet by packet and hijacked DNS carry the peer's user too, not only
// connections: per-user stats count flows from the router's RoutedFlow trackers.
func TestH_EndpointPeerUserOnFlowsAndDNS(t *testing.T) {
	router := &hPeerUserRouter{}
	ep := &Endpoint{
		Adapter:        endpoint.NewAdapter(C.TypeWireGuard, "wg-test", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:            context.Background(),
		router:         router,
		logger:         log.NewNOPFactory().NewLogger("test"),
		localAddresses: []netip.Prefix{netip.MustParsePrefix("10.8.0.1/24")},
		peerUsers: peeruser.New([]peeruser.Peer{
			{User: "alice", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.10/32")}},
		}),
	}

	ep.JudgeFlow(uint8(header.UDPProtocolNumber), netip.MustParseAddrPort("10.8.0.10:40000"), netip.MustParseAddrPort("1.1.1.1:443"), nil)
	require.Equal(t, "alice", router.metadata.User)
	ep.JudgeFlow(uint8(header.UDPProtocolNumber), netip.MustParseAddrPort("10.8.0.11:40000"), netip.MustParseAddrPort("1.1.1.1:443"), nil)
	require.Empty(t, router.metadata.User, "a peer without user")

	ep.NewDNSPacket(nil, M.ParseSocksaddr("10.8.0.10:40000"), M.ParseSocksaddr("10.8.0.1:53"), nil)
	require.Equal(t, "alice", router.metadata.User)
}
