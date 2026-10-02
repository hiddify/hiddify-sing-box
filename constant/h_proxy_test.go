package constant

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_ProxyDisplayNameHiddifyTypes(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		TypeWARP:           "WARP",
		TypeMieru:          "Mieru",
		TypeMASQUE:         "MASQUE",
		TypePsiphon:        "Psiphon",
		TypeHInvalidConfig: "Invalid",
		TypeXray:           "xray",
		TypeCustom:         "custom",
		TypeTunnelClient:   "Tunnel Client",
		TypeTunnelServer:   "Tunnel Server",
		TypeAwg:            "Awg",
		TypeBalancer:       "Balancer",
		TypeDNSTT:          "DNSTT",
		TypeGooseRelay:     "GooseRelay",
		TypeTrustTunnel:    "TrustTunnel",
	}
	for proxyType, expected := range cases {
		require.Equal(t, expected, ProxyDisplayName(proxyType), proxyType)
	}
	require.Equal(t, "Unknown", ProxyDisplayName("definitely-not-a-type"))
	require.Equal(t, "Unknown", ProxyDisplayName(""))
}

func TestH_HiddifyTypeValues(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		"TypeWARP":            TypeWARP,
		"TypeMieru":           TypeMieru,
		"TypeMASQUE":          TypeMASQUE,
		"TypePsiphon":         TypePsiphon,
		"TypeTunnelClient":    TypeTunnelClient,
		"TypeTunnelServer":    TypeTunnelServer,
		"TypeHInvalidConfig":  TypeHInvalidConfig,
		"TypeXray":            TypeXray,
		"TypeCustom":          TypeCustom,
		"TypeAwg":             TypeAwg,
		"TypeBalancer":        TypeBalancer,
		"TypeDNSTT":           TypeDNSTT,
		"TypeGooseRelay":      TypeGooseRelay,
		"TypeSmartDNSPool":    TypeSmartDNSPool,
		"TypeTrustTunnel":     TypeTrustTunnel,
		"TypeLegacyWireGuard": TypeLegacyWireGuard,
	}
	upstream := []string{
		TypeTun, TypeRedirect, TypeTProxy, TypeDirect, TypeBlock, TypeDNS, TypeSOCKS, TypeHTTP, TypeMixed,
		TypeShadowsocks, TypeVMess, TypeTrojan, TypeNaive, TypeWireGuard, TypeHysteria, TypeTor, TypeSSH,
		TypeShadowTLS, TypeVLESS, TypeTUIC, TypeHysteria2, TypeAnyTLS, TypeTailscale, TypeSelector, TypeURLTest,
		TypeMASQUEClient, TypeMASQUEServer,
	}
	seen := make(map[string]string)
	for _, value := range upstream {
		seen[value] = "upstream"
	}
	for name, value := range values {
		require.NotEmpty(t, value, name)
		previous, loaded := seen[value]
		require.False(t, loaded, "%s=%q collides with %s", name, value, previous)
		seen[value] = name
	}
	require.Equal(t, "tunnel_client", TypeTunnelClient)
	require.Equal(t, "tunnel_server", TypeTunnelServer)
	require.Equal(t, "multi", DNSTypeMulti)
	require.Equal(t, "sdns", DNSTypeSDNS)
	require.Equal(t, "xhttp", V2RayTransportTypeXHTTP)
	require.Equal(t, "raw", V2RayTransportTypeRaw)
	require.NotEmpty(t, DefaultBrowserAgent)
}
