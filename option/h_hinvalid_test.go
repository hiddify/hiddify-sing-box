package option_test

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

const hInvalidConfig = `{
  "endpoints": [
    {"type": "no-such-endpoint", "tag": "bad-endpoint"}
  ],
  "outbounds": [
    {"type": "socks", "tag": "good", "server": "127.0.0.1", "server_port": 1080},
    {"type": "vless", "tag": "bad-vless", "server": "127.0.0.1", "server_port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "unknown_field": 1},
    {"type": "no-such-type", "server": "127.0.0.1"}
  ]
}`

func TestHInvalidOptionsDoNotFailDecode(t *testing.T) {
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(hInvalidConfig))
	require.NoError(t, err)

	require.Equal(t, C.TypeSOCKS, options.Outbounds[0].Type)

	bad := options.Outbounds[1]
	require.Equal(t, C.TypeHInvalidConfig, bad.Type)
	require.Equal(t, "bad-vless", bad.Tag)
	invalid := bad.Options.(*option.HInvalidOptions)
	require.Equal(t, C.TypeVLESS, invalid.OriginalType)
	require.ErrorContains(t, invalid.Err, "outbounds[1: bad-vless]: ")
	require.ErrorContains(t, invalid.Err, "unknown_field")

	untagged := options.Outbounds[2].Options.(*option.HInvalidOptions)
	require.ErrorContains(t, untagged.Err, "outbounds[2: 2]: unknown outbound type: no-such-type")

	endpoint := options.Endpoints[0]
	require.Equal(t, C.TypeHInvalidConfig, endpoint.Type)
	require.ErrorContains(t, endpoint.Options.(*option.HInvalidOptions).Err, "endpoints[0: bad-endpoint]: unknown endpoint type")

	// re-marshalling keeps the original config of invalid entries
	content, err := json.MarshalContext(ctx, &bad)
	require.NoError(t, err)
	require.Contains(t, string(content), `"unknown_field"`)
	require.Contains(t, string(content), `"type":"vless"`)

	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	out, loaded := instance.Outbound().Outbound("bad-vless")
	require.True(t, loaded)
	require.Equal(t, C.TypeHInvalidConfig, out.Type())
	ep, loaded := instance.Endpoint().Get("bad-endpoint")
	require.True(t, loaded)
	require.Equal(t, C.TypeHInvalidConfig, ep.Type())
}
