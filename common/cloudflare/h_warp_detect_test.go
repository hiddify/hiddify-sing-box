package cloudflare

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_IsWARPHost(t *testing.T) {
	for host, want := range map[string]bool{
		"162.159.198.2":                        true,
		"162.159.198.2:443":                    true,
		"162.159.199.2":                        true, // WARP+
		"[2606:4700:103::2]:443":               true,
		"2606:4700:103::2":                     true,
		"[2606:4700:103::2]":                   true,
		"engage.cloudflareclient.com":          true,
		"consumer-masque.cloudflareclient.com": true,
		"zt-masque.cloudflareclient.com:443":   true,
		"10.0.0.1":                             false,
		"1.1.1.1:443":                          false,
		"masque.example.com":                   false,
		"cloudflareclient.com.evil.example":    false,
		"":                                     false,
	} {
		require.Equal(t, want, IsWARPHost(host), host)
	}
	require.True(t, IsWARPAddress(netip.MustParseAddr("::ffff:162.159.198.1")), "a mapped IPv4")
}
