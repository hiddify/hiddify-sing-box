package openvpn

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
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

func (r *hPeerUserRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.metadata = metadata
}

func (r *hPeerUserRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.metadata = metadata
}

func (r *hPeerUserRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	r.metadata = metadata
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (r *hPeerUserRouter) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	r.metadata = metadata
}

// Every way traffic leaves the server endpoint (connections, packet connections, flows forwarded
// packet by packet and hijacked DNS) carries the user owning the source address.
func TestH_ServerEndpointPeerUser(t *testing.T) {
	router := &hPeerUserRouter{}
	users := map[netip.Addr]string{netip.MustParseAddr("10.8.0.10"): "alice"}
	server := &ServerEndpoint{
		endpointBase: endpointBase{
			Adapter: endpoint.NewAdapter(C.TypeOpenVPNServer, "ovpn-test", []string{N.NetworkTCP, N.NetworkUDP}, nil),
			router:  router,
			logger:  log.NewNOPFactory().NewLogger("test"),
			peerUser: func(address netip.Addr) string {
				return users[address]
			},
		},
		ctx:            context.Background(),
		localAddresses: []netip.Prefix{netip.MustParsePrefix("10.8.0.1/24")},
	}
	alice := M.ParseSocksaddr("10.8.0.10:40000")
	other := M.ParseSocksaddr("10.8.0.11:40000")

	server.NewConnectionEx(context.Background(), nil, alice, M.ParseSocksaddr("1.1.1.1:443"), nil)
	require.Equal(t, "alice", router.metadata.User)
	server.NewConnectionEx(context.Background(), nil, alice, M.ParseSocksaddr("10.8.0.1:80"), nil)
	require.Equal(t, "alice", router.metadata.User, "to the server's own address")
	server.NewConnectionEx(context.Background(), nil, other, M.ParseSocksaddr("1.1.1.1:443"), nil)
	require.Empty(t, router.metadata.User, "an address no client owns")

	server.NewPacketConnectionEx(context.Background(), nil, alice, M.ParseSocksaddr("1.1.1.1:443"), nil)
	require.Equal(t, "alice", router.metadata.User)

	server.JudgeFlow(uint8(header.ICMPv4ProtocolNumber), alice.AddrPort(), netip.MustParseAddrPort("1.1.1.1:0"), nil)
	require.Equal(t, "alice", router.metadata.User)
	server.JudgeFlow(uint8(header.ICMPv4ProtocolNumber), other.AddrPort(), netip.MustParseAddrPort("1.1.1.1:0"), nil)
	require.Empty(t, router.metadata.User)

	server.NewDNSPacket(nil, alice, M.ParseSocksaddr("10.8.0.1:53"), nil)
	require.Equal(t, "alice", router.metadata.User)
}

// Before Start, and on a client endpoint, nobody owns an address.
func TestH_PeerUserWithoutServer(t *testing.T) {
	server := &ServerEndpoint{}
	server.peerUser = server.serverPeerUser
	require.Empty(t, server.lookupPeerUser(netip.MustParseAddr("10.8.0.10")))
	require.Empty(t, (&endpointBase{}).lookupPeerUser(netip.MustParseAddr("10.8.0.10")))
}
