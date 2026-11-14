package box

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// Only a client endpoint can be lazy; one that connects in the background is made on demand, so
// that the first dial waits for its tunnel, without changing the options of the config.
func TestH_LazyEndpointOptions(t *testing.T) {
	client := &option.WireGuardEndpointOptions{}
	options, canBe := lazyEndpointOptions(C.TypeWireGuard, client)
	require.True(t, canBe)
	require.Same(t, client, options)
	_, canBe = lazyEndpointOptions(C.TypeWireGuard, &option.WireGuardEndpointOptions{ListenPort: 51820})
	require.False(t, canBe, "a WireGuard that listens is a server")
	_, canBe = lazyEndpointOptions(C.TypeAwg, &option.AwgEndpointOptions{ListenPort: 51820})
	require.False(t, canBe)

	openvpn := &option.OpenVPNClientEndpointOptions{}
	options, canBe = lazyEndpointOptions(C.TypeOpenVPNClient, openvpn)
	require.True(t, canBe)
	require.True(t, options.(*option.OpenVPNClientEndpointOptions).OnDemand, "the first dial waits for the tunnel")
	require.False(t, openvpn.OnDemand, "the config's options stay as they are")
	options, canBe = lazyEndpointOptions(C.TypeOpenConnect, &option.OpenConnectEndpointOptions{})
	require.True(t, canBe)
	require.True(t, options.(*option.OpenConnectEndpointOptions).OnDemand)
	options, canBe = lazyEndpointOptions(C.TypeMASQUEClient, &option.MASQUEClientEndpointOptions{})
	require.True(t, canBe)
	require.True(t, options.(*option.MASQUEClientEndpointOptions).OnDemand)

	for _, server := range []struct {
		typ     string
		options any
	}{
		{C.TypeOpenVPNServer, &option.OpenVPNServerEndpointOptions{}},
		{C.TypeMASQUEServer, &option.MASQUEServerEndpointOptions{}},
		{C.TypeTunnelServer, &option.TunnelServerEndpointOptions{}},
		{C.TypeTunnelClient, &option.TunnelClientEndpointOptions{}},
		{C.TypeTailscale, &option.TailscaleEndpointOptions{}},
	} {
		_, canBe = lazyEndpointOptions(server.typ, server.options)
		require.False(t, canBe, server.typ)
	}
}

// A lazy endpoint keeps the config's own options for a hold from the start (a DNS server needs
// it), where those of the lazy one are made on demand.
func TestH_LazyEndpointHeldOptions(t *testing.T) {
	ctx := context.Background()
	own := &option.OpenVPNClientEndpointOptions{}
	typ, options := lazyEndpoint(ctx, option.Endpoint{Type: C.TypeOpenVPNClient, Tag: "vpn", Lazy: true, Options: own})
	require.Equal(t, C.TypeHLazy, typ)
	lazy := options.(*option.HLazyOptions)
	require.True(t, lazy.Options.(*option.OpenVPNClientEndpointOptions).OnDemand)
	require.Same(t, own, lazy.HeldOptions)
	typ, _ = lazyEndpoint(ctx, option.Endpoint{Type: C.TypeOpenVPNClient, Tag: "vpn", Options: own})
	require.Equal(t, C.TypeOpenVPNClient, typ, "only when asked for")
}
