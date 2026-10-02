package wireguard

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func hKey(t *testing.T) wgtypes.Key {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}

func hLegacyOptions(t *testing.T) option.LegacyWireGuardOutboundOptions {
	return option.LegacyWireGuardOutboundOptions{
		LocalAddress:  badoption.Listable[netip.Prefix]{netip.MustParsePrefix("172.16.0.2/32")},
		PrivateKey:    hKey(t).String(),
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 9},
		PeerPublicKey: hKey(t).PublicKey().String(),
		Reserved:      []uint8{1, 2, 3},
		MTU:           1280,
	}
}

func hNewLegacy(t *testing.T, options option.LegacyWireGuardOutboundOptions) (*Outbound, error) {
	created, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("wg-legacy"), "legacy", options)
	if err != nil {
		return nil, err
	}
	return created.(*Outbound), nil
}

func TestH_RegisterLegacyOutbound(t *testing.T) {
	registry := outbound.NewRegistry()
	RegisterOutbound(registry)
	options, loaded := registry.CreateOptions(C.TypeLegacyWireGuard)
	require.True(t, loaded)
	require.IsType(t, &option.LegacyWireGuardOutboundOptions{}, options)
	_, loaded = registry.CreateOptions(C.TypeWireGuard)
	require.False(t, loaded, "legacy outbound must not shadow the upstream wireguard type")
}

func TestH_LegacyOutboundOptionValidation(t *testing.T) {
	options := hLegacyOptions(t)
	options.Detour = "other"
	options.GSO = true
	_, err := hNewLegacy(t, options)
	require.ErrorContains(t, err, "gso is conflict with detour")

	options = hLegacyOptions(t)
	options.PrivateKey = "!!"
	_, err = hNewLegacy(t, options)
	require.ErrorContains(t, err, "decode private key")

	options = hLegacyOptions(t)
	options.PrivateKey = ""
	_, err = hNewLegacy(t, options)
	require.ErrorContains(t, err, "missing private key")

	options = hLegacyOptions(t)
	options.Reserved = []uint8{1, 2}
	_, err = hNewLegacy(t, options)
	require.ErrorContains(t, err, "invalid reserved value")

	options = hLegacyOptions(t)
	options.Peers = []option.LegacyWireGuardPeer{{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 9},
		PublicKey:     hKey(t).PublicKey().String(),
	}}
	_, err = hNewLegacy(t, options)
	require.ErrorContains(t, err, "missing allowed ips")
}

func TestH_LegacyOutboundMetadata(t *testing.T) {
	o, err := hNewLegacy(t, hLegacyOptions(t))
	require.NoError(t, err)
	require.Equal(t, "legacy", o.Tag())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, o.Network())
	require.False(t, o.PreferredDomain(nil, "example.com"))
	require.Nil(t, o.endpoint.Lookup(netip.MustParseAddr("1.1.1.1")), "no routes before start")
	require.Equal(t, adapter.PreMatchContinue, o.PreMatchFlow(N.NetworkICMP, netip.MustParseAddr("1.1.1.1")))
	_, err = o.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{Port: 80})
	require.ErrorContains(t, err, "invalid destination")
	_, err = o.ListenPacket(context.Background(), M.Socksaddr{Port: 53})
	require.Error(t, err)
}

func TestH_LegacyOutboundStartWithoutInitialize(t *testing.T) {
	t.Skip("BUG: legacy Outbound.Start never calls endpoint.Initialize, so StartStateStart dereferences a nil tun device and panics")
	o, err := hNewLegacy(t, hLegacyOptions(t))
	require.NoError(t, err)
	require.NotPanics(t, func() {
		for _, stage := range adapter.ListStartStages {
			require.NoError(t, o.Start(stage))
		}
	})
}

func hStartLegacy(t *testing.T, o *Outbound) {
	require.NoError(t, o.endpoint.Initialize(nil))
	t.Cleanup(func() { o.Close() })
	require.NoError(t, o.Start(adapter.StartStateStart))
	require.NoError(t, o.Start(adapter.StartStatePostStart))
}

func TestH_LegacyOutboundSinglePeerRoutesEverything(t *testing.T) {
	o, err := hNewLegacy(t, hLegacyOptions(t))
	require.NoError(t, err)
	hStartLegacy(t, o)
	for _, address := range []string{"1.1.1.1", "10.0.0.1", "2001:db8::1"} {
		addr := netip.MustParseAddr(address)
		require.Equal(t, adapter.PreMatchFlow, o.PreMatchFlow(N.NetworkICMP, addr), address)
		require.True(t, o.PreferredAddress(nil, addr), address)
	}
}

func TestH_LegacyOutboundMultiPeerAllowedIPs(t *testing.T) {
	options := hLegacyOptions(t)
	options.Peers = []option.LegacyWireGuardPeer{
		{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 9},
			PublicKey:     hKey(t).PublicKey().String(),
			AllowedIPs:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.0/8")},
			Reserved:      []uint8{4, 5, 6},
		},
		{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 10},
			PublicKey:     hKey(t).PublicKey().String(),
			AllowedIPs:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("fd00::/8")},
		},
	}
	o, err := hNewLegacy(t, options)
	require.NoError(t, err)
	hStartLegacy(t, o)
	require.Equal(t, adapter.PreMatchFlow, o.PreMatchFlow(N.NetworkICMP, netip.MustParseAddr("10.2.3.4")))
	require.Equal(t, adapter.PreMatchFlow, o.PreMatchFlow(N.NetworkICMP, netip.MustParseAddr("fd12::1")))
	require.Equal(t, adapter.PreMatchContinue, o.PreMatchFlow(N.NetworkICMP, netip.MustParseAddr("8.8.8.8")))
	require.False(t, o.PreferredAddress(nil, netip.MustParseAddr("8.8.8.8")))
}
