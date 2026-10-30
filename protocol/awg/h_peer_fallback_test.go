package awg

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/stretchr/testify/require"
)

func TestH_PeerFallbackOptions(t *testing.T) {
	fallback := badoption.Listable[netip.Addr]{netip.MustParseAddr("2606:4700:d0::1")}
	addresses, err := peerFallback(option.AwgEndpointOptions{
		Peers:           []option.AwgPeerOptions{{Address: "162.159.192.1", Port: 2408}},
		FallbackAddress: fallback,
	})
	require.NoError(t, err)
	require.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("[2606:4700:d0::1]:2408")}, addresses)
	_, err = peerFallback(option.AwgEndpointOptions{
		Peers:           []option.AwgPeerOptions{{Address: "engage.cloudflareclient.com", Port: 2408}},
		FallbackAddress: fallback,
	})
	require.ErrorContains(t, err, "single peer with an IP address")
}
