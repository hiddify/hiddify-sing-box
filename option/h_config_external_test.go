package option_test

import (
	"context"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

const hTunnelConfig = `{
  "endpoints": [
    {
      "type": "tunnel_server",
      "tag": "ts",
      "uuid": "33333333-3333-3333-3333-333333333333",
      "users": [{"uuid": "11111111-1111-1111-1111-111111111111", "key": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}],
      "inbound": {"type": "vless", "tag": "ts-in", "listen": "127.0.0.1", "listen_port": 10443, "users": [{"uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]},
      "connect_timeout": "3s"
    },
    {
      "type": "tunnel_client",
      "tag": "tc",
      "uuid": "11111111-1111-1111-1111-111111111111",
      "key": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "outbound": {"type": "vless", "tag": "tc-out", "server": "127.0.0.1", "server_port": 10443, "uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}
    }
  ],
  "route": {
    "rules": [
      {"tunnel_source": "11111111-1111-1111-1111-111111111111", "action": "route", "outbound": "ts", "override_tunnel_destination": "22222222-2222-2222-2222-222222222222"},
      {"tunnel_destination": ["33333333-3333-3333-3333-333333333333"], "outbound": "direct"}
    ]
  }
}`

func TestH_TunnelConfigParse(t *testing.T) {
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(hTunnelConfig))
	require.NoError(t, err)
	require.Len(t, options.Endpoints, 2)

	server, ok := options.Endpoints[0].Options.(*option.TunnelServerEndpointOptions)
	require.True(t, ok)
	require.Equal(t, C.TypeTunnelServer, options.Endpoints[0].Type)
	require.Equal(t, "33333333-3333-3333-3333-333333333333", server.UUID)
	require.Len(t, server.Users, 1)
	require.Equal(t, 3*time.Second, time.Duration(server.ConnectTimeout))
	require.Equal(t, C.TypeVLESS, server.Inbound.Type)
	inboundOptions, ok := server.Inbound.Options.(*option.VLESSInboundOptions)
	require.True(t, ok)
	require.Equal(t, uint16(10443), inboundOptions.ListenPort)

	client, ok := options.Endpoints[1].Options.(*option.TunnelClientEndpointOptions)
	require.True(t, ok)
	require.Equal(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", client.Key)
	require.Equal(t, "tc-out", client.Outbound.Tag)
	_, ok = client.Outbound.Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)

	require.NotNil(t, options.Route)
	require.Len(t, options.Route.Rules, 2)
	first := options.Route.Rules[0].DefaultOptions
	require.Equal(t, []string{"11111111-1111-1111-1111-111111111111"}, []string(first.TunnelSource))
	require.Equal(t, "22222222-2222-2222-2222-222222222222", first.RouteOptions.OverrideTunnelDestination)

	encoded, err := json.MarshalContext(ctx, options)
	require.NoError(t, err)
	reparsed, err := json.UnmarshalExtendedContext[option.Options](ctx, encoded)
	require.NoError(t, err)
	reencoded, err := json.MarshalContext(ctx, reparsed)
	require.NoError(t, err)
	require.JSONEq(t, string(encoded), string(reencoded))
}

func TestH_TunnelConfigInvalidNested(t *testing.T) {
	ctx := include.Context(context.Background())
	// H: an invalid nested outbound becomes an hinvalid placeholder instead of failing the config
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"endpoints":[{"type":"tunnel_client","tag":"tc","outbound":{"type":"h-unknown"}}]}`))
	require.NoError(t, err)
	client, ok := options.Endpoints[0].Options.(*option.TunnelClientEndpointOptions)
	require.True(t, ok)
	require.Equal(t, C.TypeHInvalidConfig, client.Outbound.Type)
	options, err = json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"endpoints":[{"type":"tunnel_server","tag":"ts","inbound":{"type":"h-unknown"}}]}`))
	require.NoError(t, err)
	require.Equal(t, C.TypeHInvalidConfig, options.Endpoints[0].Type)
	require.ErrorContains(t, options.Endpoints[0].Options.(*option.HInvalidOptions).Err, "endpoints[0: ts]: inbound")
}
