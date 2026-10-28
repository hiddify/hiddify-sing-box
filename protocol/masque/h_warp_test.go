package masque

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// The profile writes its endpoints with a port; the IP must come out whole, IPv6 too.
func TestH_EndpointHost(t *testing.T) {
	for endpoint, want := range map[string]string{
		"162.159.198.1:0":        "162.159.198.1",
		"162.159.198.1:443":      "162.159.198.1",
		"[2606:4700:103::1]:0":   "2606:4700:103::1",
		"[2606:4700:103::1]:443": "2606:4700:103::1",
		"162.159.198.1":          "162.159.198.1",
		"":                       "",
	} {
		require.Equal(t, want, endpointHost(endpoint), endpoint)
	}
}

func TestH_ConfigAddresses(t *testing.T) {
	addresses, err := (&Config{IPv4: "172.16.0.2", IPv6: "2606:4700:110:8a36::1"}).Addresses()
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32"), netip.MustParsePrefix("2606:4700:110:8a36::1/128")}, addresses)
	addresses, err = (&Config{IPv4: "172.16.0.2"}).Addresses()
	require.NoError(t, err)
	require.Len(t, addresses, 1, "a missing family is skipped")
	_, err = (&Config{}).Addresses()
	require.Error(t, err)
	_, err = (&Config{IPv4: "not-an-ip"}).Addresses()
	require.Error(t, err)
}
