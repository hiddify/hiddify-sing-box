package wireguard

import (
	"net/netip"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// peerFallback is the only peer's fallback addresses, on its port (see
// transport/wireguard/h_peer_fallback.go). They need a single peer given by an IP address.
func peerFallback(options option.WireGuardEndpointOptions) ([]netip.AddrPort, error) {
	if len(options.FallbackAddress) == 0 {
		return nil, nil
	}
	if len(options.Peers) != 1 || !M.ParseAddr(options.Peers[0].Address).IsValid() {
		return nil, E.New("wireguard: fallback_address needs a single peer with an IP address")
	}
	addresses := make([]netip.AddrPort, 0, len(options.FallbackAddress))
	for _, address := range options.FallbackAddress {
		addresses = append(addresses, netip.AddrPortFrom(address, options.Peers[0].Port))
	}
	return addresses, nil
}
