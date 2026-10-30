package wireguard

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

// A move redials a bind connected to the peer's address, and only that kind of bind.
func TestH_PeerFallbackMove(t *testing.T) {
	v4, v6 := netip.MustParseAddrPort("162.159.192.1:2408"), netip.MustParseAddrPort("[2606:4700:d0::1]:2408")
	e := &Endpoint{
		options: EndpointOptions{Context: context.Background(), Logger: logger.NOP(), PeerFallback: []netip.AddrPort{v6}},
		peers:   []peerConfig{{endpoint: v4}},
	}
	connected := NewClientBind(context.Background(), logger.NOP(), nil, true, v4, [3]uint8{})
	f := newPeerFallback(e, connected)
	f.Check() // nothing sent: no move
	if connected.connectAddr != v4 {
		t.Fatal("moved while idle")
	}
	if newPeerFallback(&Endpoint{options: e.options, peers: []peerConfig{{}}}, connected) != nil {
		t.Error("a peer without an IP address got a fallback")
	}
	e.fallback = f
	e.pathChanged() // on the first address: nothing to move, no panic without a prober
}
