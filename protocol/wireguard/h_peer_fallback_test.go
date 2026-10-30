package wireguard

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestH_PeerFallbackOptions(t *testing.T) {
	options := func(change func(*option.WireGuardEndpointOptions)) option.WireGuardEndpointOptions {
		o := option.WireGuardEndpointOptions{
			Peers:           []option.WireGuardPeer{{Address: "162.159.192.1", Port: 2408}},
			FallbackAddress: badoption.Listable[netip.Addr]{netip.MustParseAddr("2606:4700:d0::1")},
		}
		change(&o)
		return o
	}
	addresses, err := peerFallback(options(func(*option.WireGuardEndpointOptions) {}))
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddrPort("[2606:4700:d0::1]:2408") {
		t.Fatalf("%v %v", addresses, err)
	}
	for name, change := range map[string]func(*option.WireGuardEndpointOptions){
		"a domain peer": func(o *option.WireGuardEndpointOptions) { o.Peers[0].Address = "engage.cloudflareclient.com" },
		"two peers":     func(o *option.WireGuardEndpointOptions) { o.Peers = append(o.Peers, o.Peers[0]) },
	} {
		if _, err := peerFallback(options(change)); err == nil {
			t.Errorf("%s: loads, but the fallback cannot run", name)
		}
	}
}
